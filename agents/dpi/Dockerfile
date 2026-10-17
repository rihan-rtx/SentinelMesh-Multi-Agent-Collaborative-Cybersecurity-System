FROM python:3.11-slim

WORKDIR /app

COPY shared/ /app/shared/
COPY agents/dpi/ /app/agents/dpi/

RUN pip install --no-cache-dir -r /app/agents/dpi/requirements.txt

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "agents.dpi.main"]
