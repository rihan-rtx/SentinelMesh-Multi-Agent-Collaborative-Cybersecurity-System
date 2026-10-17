FROM python:3.11-slim

WORKDIR /app

COPY shared/ /app/shared/
COPY agents/correlation/ /app/agents/correlation/

RUN pip install --no-cache-dir -r /app/agents/correlation/requirements.txt

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "agents.correlation.main"]
