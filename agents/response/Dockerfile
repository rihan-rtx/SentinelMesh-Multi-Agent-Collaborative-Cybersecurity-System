FROM python:3.11-slim

WORKDIR /app

COPY shared/ /app/shared/
COPY agents/response/ /app/agents/response/

RUN pip install --no-cache-dir -r /app/agents/response/requirements.txt

# Create audit log directory
RUN mkdir -p /var/log/sentinelmesh

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "agents.response.main"]
