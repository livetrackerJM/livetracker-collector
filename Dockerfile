# LiveTracker Collector - polls network devices over SNMP and reports to LiveTracker.
FROM python:3.12-slim

# net-snmp command-line tools (snmpget / snmpbulkwalk) - the only runtime dependency.
RUN apt-get update \
 && apt-get install -y --no-install-recommends snmp ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin collector \
 && mkdir -p /data && chown collector /data

WORKDIR /app
COPY collector ./collector

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LT_STATE_DIR=/data \
    MIBS=""

USER collector
VOLUME ["/data"]
ENTRYPOINT ["python", "-m", "collector"]
