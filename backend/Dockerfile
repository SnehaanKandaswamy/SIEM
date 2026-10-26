# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /build
COPY requirements.txt .
RUN python -m venv /opt/venv && /opt/venv/bin/pip install -r requirements.txt

FROM python:3.12-slim AS runtime
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PATH=/opt/venv/bin:$PATH
RUN groupadd --system --gid 10001 siem && useradd --system --uid 10001 --gid siem --home /app --shell /usr/sbin/nologin siem
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=siem:siem app ./app
COPY --chown=siem:siem alembic ./alembic
COPY --chown=siem:siem alembic.ini pyproject.toml ./
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3).status==200 else 1)"
# Single worker: the live-stream buffer and rate limiters are in-process. --no-access-log avoids log feedback
# loops with the log collector; request metrics are exported to Prometheus instead.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--proxy-headers", "--forwarded-allow-ips", "*", "--timeout-graceful-shutdown", "20"]
