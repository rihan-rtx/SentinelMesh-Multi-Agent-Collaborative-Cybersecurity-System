FROM python:3.11-slim

WORKDIR /app

COPY shared/ /app/shared/
COPY agents/coordinator/ /app/agents/coordinator/

RUN pip install --no-cache-dir -r /app/agents/coordinator/requirements.txt

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "agents.coordinator.main"]
