FROM python:3.11-slim

WORKDIR /app

COPY shared/ /app/shared/
COPY agents/dashboard_writer/ /app/agents/dashboard_writer/

RUN pip install --no-cache-dir -r /app/agents/dashboard_writer/requirements.txt

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "agents.dashboard_writer.main"]
