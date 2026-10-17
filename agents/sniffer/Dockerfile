FROM python:3.11-slim

WORKDIR /app

# Install libpcap for Scapy live capture
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy shared module and agent code
COPY shared/ /app/shared/
COPY agents/sniffer/ /app/agents/sniffer/

# Install agent requirements
RUN pip install --no-cache-dir -r /app/agents/sniffer/requirements.txt

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "agents.sniffer.main"]
