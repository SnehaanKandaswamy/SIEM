"""Event storage. OpenSearchStore is the production backend; MemoryStore is for tests and
OpenSearch-less development. Both implement the same interface."""

from __future__ import annotations

import json
import logging
import threading
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

log = logging.getLogger("siem.store")

TEMPLATE_VERSION = 1
RETENTION_DAYS = 30


class SearchError(ValueError):
    """Raised for invalid search input (mapped to HTTP 400)."""


@dataclass
class SearchParams:
    q: str = ""
    start: datetime | None = None
    end: datetime | None = None
    hosts: list[str] = field(default_factory=list)
    source_types: list[str] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    outcomes: list[str] = field(default_factory=list)
    src_ip: str | None = None
    user: str | None = None
    synthetic: bool | None = None
    page: int = 1
    size: int = 50
    sort_field: str = "@timestamp"
    sort_order: str = "desc"


SORTABLE = {"@timestamp", "severity", "host", "source_type"}


class EventStore(Protocol):
    def ensure_ready(self) -> None: ...
    def index(self, events: list[dict]) -> tuple[int, int]: ...
    def search(self, p: SearchParams) -> tuple[int, list[dict]]: ...
    def fetch(self, since: datetime, filters: dict[str, Any], limit: int = 5000) -> list[dict]: ...
    def get_many(self, ids: list[str]) -> list[dict]: ...
    def stats(self, since: datetime, bucket_minutes: int) -> dict: ...
    def mark_detections(self, event_ids: list[str], rule_id: str) -> None: ...
    def health(self) -> dict: ...


def _ts(e: dict) -> datetime:
    return datetime.fromisoformat(e["@timestamp"])


def _match_filters(e: dict, filters: dict[str, Any]) -> bool:
    for k, want in filters.items():
        have = e.get(k)
        if isinstance(want, (list, tuple, set)):
            if have not in want:
                return False
        elif want is None:
            if have is not None:
                return False
        elif have != want:
            return False
    return True


class MemoryStore:
    def __init__(self) -> None:
        self._events: dict[str, dict] = {}
        self._lock = threading.Lock()

    def ensure_ready(self) -> None:
        pass

    def index(self, events: list[dict]) -> tuple[int, int]:
        new = dup = 0
        with self._lock:
            for e in events:
                if e["event_id"] in self._events:
                    dup += 1
                else:
                    self._events[e["event_id"]] = e
                    new += 1
        return new, dup

    def _all(self) -> list[dict]:
        with self._lock:
            return list(self._events.values())

    def search(self, p: SearchParams) -> tuple[int, list[dict]]:
        if p.sort_field not in SORTABLE or p.sort_order not in ("asc", "desc"):
            raise SearchError("invalid sort")
        terms = p.q.lower().split()
        out = []
        for e in self._all():
            t = _ts(e)
            if (p.start and t < p.start) or (p.end and t > p.end):
                continue
            if p.hosts and e["host"] not in p.hosts:
                continue
            if p.source_types and e["source_type"] not in p.source_types:
                continue
            if p.severities and e["severity"] not in p.severities:
                continue
            if p.categories and e["category"] not in p.categories:
                continue
            if p.actions and e["action"] not in p.actions:
                continue
            if p.outcomes and e["outcome"] not in p.outcomes:
                continue
            if p.src_ip and e.get("src_ip") != p.src_ip:
                continue
            if p.user and e.get("user") != p.user:
                continue
            if p.synthetic is not None and e.get("synthetic") != p.synthetic:
                continue
            if terms:
                hay = " ".join(
                    str(e.get(k) or "") for k in ("message", "raw", "user", "command_line", "host", "src_ip")
                ).lower()
                if not all(term in hay for term in terms):
                    continue
            out.append(e)
        out.sort(key=lambda e: e[p.sort_field], reverse=p.sort_order == "desc")
        start = (p.page - 1) * p.size
        return len(out), out[start : start + p.size]

    def fetch(self, since: datetime, filters: dict[str, Any], limit: int = 5000) -> list[dict]:
        res = [e for e in self._all() if _ts(e) >= since and _match_filters(e, filters)]
        res.sort(key=_ts)
        return res[-limit:]

    def get_many(self, ids: list[str]) -> list[dict]:
        with self._lock:
            return [self._events[i] for i in ids if i in self._events]

    def mark_detections(self, event_ids: list[str], rule_id: str) -> None:
        with self._lock:
            for i in event_ids:
                e = self._events.get(i)
                if e is not None and rule_id not in e["detections"]:
                    e["detections"] = [*e["detections"], rule_id]

    def stats(self, since: datetime, bucket_minutes: int) -> dict:
        evs = [e for e in self._all() if _ts(e) >= since]
        buckets: Counter = Counter()
        for e in evs:
            t = _ts(e)
            t = t.replace(
                second=0,
                microsecond=0,
                minute=(t.minute // bucket_minutes) * bucket_minutes if bucket_minutes < 60 else 0,
            )
            buckets[t.isoformat()] += 1
        return {
            "total_all": len(self._events),
            "total_window": len(evs),
            "timeline": [{"t": k, "count": v} for k, v in sorted(buckets.items())],
            "top_src_ips": [
                {"key": k, "count": v} for k, v in Counter(e["src_ip"] for e in evs if e.get("src_ip")).most_common(10)
            ],
            "top_hosts": [{"key": k, "count": v} for k, v in Counter(e["host"] for e in evs).most_common(10)],
            "by_source_type": [{"key": k, "count": v} for k, v in Counter(e["source_type"] for e in evs).most_common()],
        }

    def health(self) -> dict:
        return {"status": "green", "backend": "memory", "documents": len(self._events)}


class OpenSearchStore:
    def __init__(self, url: str, user: str = "", password: str = "", verify: bool = False, prefix: str = "siem-events"):
        from opensearchpy import OpenSearch

        self.prefix = prefix
        auth = (user, password) if user else None
        self.client = OpenSearch(
            hosts=[url],
            http_auth=auth,
            use_ssl=url.startswith("https"),
            verify_certs=verify,
            ssl_show_warn=False,
            timeout=15,
            max_retries=3,
            retry_on_timeout=True,
        )

    @property
    def pattern(self) -> str:
        return f"{self.prefix}-*"

    def _index_for(self, e: dict) -> str:
        return f"{self.prefix}-{_ts(e):%Y.%m.%d}"

    def ensure_ready(self) -> None:
        """Idempotent: only (re)writes the template when its version changes; never reindexes."""
        name = f"{self.prefix}-template"
        try:
            cur = self.client.indices.get_index_template(name=name)
            ver = cur["index_templates"][0]["index_template"].get("version")
        except Exception:
            ver = None
        if ver != TEMPLATE_VERSION:
            self.client.indices.put_index_template(name=name, body=_template(self.pattern))
            log.info("installed index template %s v%s", name, TEMPLATE_VERSION)
        try:  # retention policy (ISM). Optional: skip quietly if plugin is unavailable.
            self.client.transport.perform_request(
                "PUT", "/_plugins/_ism/policies/siem-retention", body=_ism_policy(self.pattern)
            )
        except Exception as e:  # already exists (409) or plugin missing
            log.debug("ISM policy not (re)created: %s", e)

    def index(self, events: list[dict]) -> tuple[int, int]:
        if not events:
            return 0, 0
        body = []
        for e in events:
            body.append(json.dumps({"create": {"_index": self._index_for(e), "_id": e["event_id"]}}))
            body.append(json.dumps(e, default=str))
        res = self.client.bulk(body="\n".join(body) + "\n", refresh=False)
        new = dup = 0
        for item in res["items"]:
            r = item["create"]
            if r.get("status") in (200, 201):
                new += 1
            elif r.get("status") == 409:
                dup += 1
            else:
                raise RuntimeError(f"bulk index error: {r.get('error')}")
        return new, dup

    def _filter_clauses(self, p: SearchParams) -> list[dict]:
        f: list[dict] = []
        rng: dict[str, str] = {}
        if p.start:
            rng["gte"] = p.start.isoformat()
        if p.end:
            rng["lte"] = p.end.isoformat()
        if rng:
            f.append({"range": {"@timestamp": rng}})
        for fld, vals in (
            ("host", p.hosts),
            ("source_type", p.source_types),
            ("severity", p.severities),
            ("category", p.categories),
            ("action", p.actions),
            ("outcome", p.outcomes),
        ):
            if vals:
                f.append({"terms": {fld: vals}})
        if p.src_ip:
            f.append({"term": {"src_ip": p.src_ip}})
        if p.user:
            f.append({"term": {"user": p.user}})
        if p.synthetic is not None:
            f.append({"term": {"synthetic": p.synthetic}})
        return f

    def search(self, p: SearchParams) -> tuple[int, list[dict]]:
        if p.sort_field not in SORTABLE or p.sort_order not in ("asc", "desc"):
            raise SearchError("invalid sort")
        must: list[dict] = []
        if p.q.strip():
            # simple_query_string never throws on malformed syntax and cannot inject query DSL.
            must.append(
                {
                    "simple_query_string": {
                        "query": p.q[:500],
                        "fields": ["message^2", "raw", "user", "command_line", "host", "process_name"],
                        "default_operator": "and",
                        "lenient": True,
                    }
                }
            )
        body = {
            "query": {"bool": {"must": must, "filter": self._filter_clauses(p)}},
            "sort": [{p.sort_field: {"order": p.sort_order, "unmapped_type": "keyword"}}],
            "from": (p.page - 1) * p.size,
            "size": p.size,
            "track_total_hits": True,
        }
        try:
            res = self.client.search(index=self.pattern, body=body, ignore_unavailable=True, allow_no_indices=True)
        except Exception as e:
            from opensearchpy.exceptions import RequestError

            if isinstance(e, RequestError):
                raise SearchError("invalid search request") from e
            raise
        return res["hits"]["total"]["value"], [h["_source"] for h in res["hits"]["hits"]]

    def fetch(self, since: datetime, filters: dict[str, Any], limit: int = 5000) -> list[dict]:
        f: list[dict] = [{"range": {"@timestamp": {"gte": since.isoformat()}}}]
        for k, v in filters.items():
            if isinstance(v, (list, tuple, set)):
                f.append({"terms": {k: list(v)}})
            elif v is None:
                f.append({"bool": {"must_not": {"exists": {"field": k}}}})
            else:
                f.append({"term": {k: v}})
        self.client.indices.refresh(index=self.pattern, ignore_unavailable=True, allow_no_indices=True)
        res = self.client.search(
            index=self.pattern,
            ignore_unavailable=True,
            allow_no_indices=True,
            body={"query": {"bool": {"filter": f}}, "sort": [{"@timestamp": "asc"}], "size": limit},
        )
        return [h["_source"] for h in res["hits"]["hits"]]

    def get_many(self, ids: list[str]) -> list[dict]:
        if not ids:
            return []
        res = self.client.search(
            index=self.pattern,
            ignore_unavailable=True,
            allow_no_indices=True,
            body={"query": {"ids": {"values": ids[:500]}}, "size": min(len(ids), 500)},
        )
        return [h["_source"] for h in res["hits"]["hits"]]

    def mark_detections(self, event_ids: list[str], rule_id: str) -> None:
        if not event_ids:
            return
        self.client.update_by_query(
            index=self.pattern,
            refresh=True,
            conflicts="proceed",
            ignore_unavailable=True,
            body={
                "query": {"ids": {"values": event_ids[:500]}},
                "script": {
                    "lang": "painless",
                    "source": "if (ctx._source.detections == null) { ctx._source.detections = [] } "
                    "if (!ctx._source.detections.contains(params.r)) { ctx._source.detections.add(params.r) }",
                    "params": {"r": rule_id},
                },
            },
        )

    def stats(self, since: datetime, bucket_minutes: int) -> dict:
        body = {
            "size": 0,
            "track_total_hits": True,
            "query": {"range": {"@timestamp": {"gte": since.isoformat()}}},
            "aggs": {
                "timeline": {"date_histogram": {"field": "@timestamp", "fixed_interval": f"{bucket_minutes}m"}},
                "ips": {"terms": {"field": "src_ip", "size": 10}},
                "hosts": {"terms": {"field": "host", "size": 10}},
                "types": {"terms": {"field": "source_type", "size": 10}},
            },
        }
        res = self.client.search(index=self.pattern, body=body, ignore_unavailable=True, allow_no_indices=True)
        a = res["aggregations"]
        total_all = self.client.count(index=self.pattern, ignore_unavailable=True, allow_no_indices=True)["count"]
        bk = lambda agg: [{"key": b["key"], "count": b["doc_count"]} for b in a[agg]["buckets"]]  # noqa: E731
        return {
            "total_all": total_all,
            "total_window": res["hits"]["total"]["value"],
            "timeline": [{"t": b["key_as_string"], "count": b["doc_count"]} for b in a["timeline"]["buckets"]],
            "top_src_ips": bk("ips"),
            "top_hosts": bk("hosts"),
            "by_source_type": bk("types"),
        }

    def health(self) -> dict:
        h = self.client.cluster.health()
        return {"status": h["status"], "backend": "opensearch", "nodes": h["number_of_nodes"]}


def _template(pattern: str) -> dict:
    kw = {"type": "keyword"}
    return {
        "index_patterns": [pattern],
        "version": TEMPLATE_VERSION,
        "priority": 100,
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "analysis": {
                    "filter": {"siem_split": {"type": "word_delimiter_graph", "preserve_original": True}},
                    # splits powershell.exe / C:\Windows\x.exe / user_name into searchable parts
                    "analyzer": {
                        "siem_text": {"type": "custom", "tokenizer": "standard", "filter": ["siem_split", "lowercase"]}
                    },
                },
            },
            "mappings": {
                "dynamic": False,
                "properties": {
                    "event_id": kw,
                    "@timestamp": {"type": "date"},
                    "host": kw,
                    "source_type": kw,
                    "category": kw,
                    "action": kw,
                    "outcome": kw,
                    "severity": kw,
                    "user": kw,
                    "src_ip": {"type": "ip"},
                    "dst_ip": {"type": "ip"},
                    "src_port": {"type": "integer"},
                    "dst_port": {"type": "integer"},
                    "process_name": {"type": "keyword", "fields": {"text": {"type": "text"}}},
                    "command_line": {"type": "text", "analyzer": "siem_text"},
                    "file_hash": kw,
                    "domain": kw,
                    "message": {"type": "text", "analyzer": "siem_text"},
                    "raw": {"type": "text", "analyzer": "siem_text"},
                    "fields": {"type": "object", "enabled": False},
                    "geo": {"properties": {"scope": kw, "country": kw, "city": kw, "location": {"type": "geo_point"}}},
                    "synthetic": {"type": "boolean"},
                    "detections": kw,
                },
            },
        },
    }


def _ism_policy(pattern: str) -> dict:
    return {
        "policy": {
            "description": f"Delete events after {RETENTION_DAYS} days",
            "default_state": "hot",
            "states": [
                {
                    "name": "hot",
                    "actions": [],
                    "transitions": [{"state_name": "delete", "conditions": {"min_index_age": f"{RETENTION_DAYS}d"}}],
                },
                {"name": "delete", "actions": [{"delete": {}}], "transitions": []},
            ],
            "ism_template": [{"index_patterns": [pattern], "priority": 100}],
        }
    }


def build_store(settings) -> EventStore:
    if settings.opensearch_url:
        return OpenSearchStore(
            settings.opensearch_url,
            settings.opensearch_user,
            settings.opensearch_password,
            settings.opensearch_verify_certs,
            settings.index_prefix,
        )
    log.warning("SIEM_OPENSEARCH_URL not set: using in-memory event store (not for production)")
    return MemoryStore()


def window_start(minutes: int) -> datetime:
    return datetime.now(UTC) - timedelta(minutes=minutes)
