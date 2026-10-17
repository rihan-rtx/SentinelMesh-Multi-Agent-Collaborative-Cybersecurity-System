FROM python:3.11-slim

WORKDIR /app

COPY shared/ /app/shared/
COPY agents/detection/ /app/agents/detection/

RUN pip install --no-cache-dir -r /app/agents/detection/requirements.txt

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "agents.detection.main"]
