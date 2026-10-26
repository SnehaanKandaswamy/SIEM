"""GeoIP enrichment. Never invents coordinates: unknown public IPs are reported as unlocated.

Sources (first match wins): a MaxMind GeoLite2-City .mmdb (SIEM_GEOIP_DB_PATH, optional dependency
`maxminddb`), then a static CIDR->location JSON file (SIEM_GEOIP_STATIC_PATH) for offline demos.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from functools import lru_cache

log = logging.getLogger("siem.geo")


class GeoResolver:
    def __init__(self, mmdb_path: str = "", static_path: str = "") -> None:
        self._reader = None
        self._static: list[tuple[ipaddress._BaseNetwork, dict]] = []
        if mmdb_path:
            try:
                import maxminddb

                self._reader = maxminddb.open_database(mmdb_path)
            except Exception as e:
                log.error("GeoIP database unavailable (%s); public IPs will be unlocated", e)
        if static_path:
            try:
                with open(static_path, encoding="utf-8") as f:
                    for cidr, info in json.load(f).items():
                        self._static.append((ipaddress.ip_network(cidr, strict=False), info))
            except Exception as e:
                log.error("static GeoIP file unavailable: %s", e)

    @staticmethod
    def scope(ip: str) -> str:
        a = ipaddress.ip_address(ip)
        if a.is_loopback:
            return "loopback"
        if a.is_private:
            return "private"
        if a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified:
            return "reserved"
        return "public"

    def lookup(self, ip: str | None) -> dict | None:
        if not ip:
            return None
        try:
            scope = self.scope(ip)
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, info in self._static:  # operator-supplied mappings win (used for labelled demo ranges)
            if a in net:
                return {**self._shape(info), "scope": scope, "source": "static"}
        if scope != "public":
            return {"scope": scope, "located": False}
        if self._reader is not None:
            try:
                r = self._reader.get(ip)
            except Exception:
                r = None
            if r and r.get("location", {}).get("latitude") is not None:
                return self._shape(
                    {
                        "lat": r["location"]["latitude"],
                        "lon": r["location"]["longitude"],
                        "country": (r.get("country") or {}).get("iso_code", ""),
                        "city": ((r.get("city") or {}).get("names") or {}).get("en", ""),
                    }
                )
        return {"scope": "public", "located": False}

    @staticmethod
    def _shape(info: dict) -> dict:
        return {
            "scope": "public",
            "located": True,
            "country": info.get("country", ""),
            "city": info.get("city", ""),
            "location": {"lat": float(info["lat"]), "lon": float(info["lon"])},
        }


@lru_cache
def get_resolver() -> GeoResolver:
    from ..config import get_settings

    s = get_settings()
    return GeoResolver(s.geoip_db_path, s.geoip_static_path)
