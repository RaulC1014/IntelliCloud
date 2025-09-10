FROM python:3.12-slim

# OS deps (psycopg2-binary needs libpq at runtime is bundled; we add curl for healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY intellicloud-backend/requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip && \
    python -m pip install --no-cache-dir -r requirements.txt

# Copy app
COPY intellicloud-backend /app

# Default envs
ENV PYTHONUNBUFFERED=1 \
    FLASK_ENV=development \
    PORT=5000

EXPOSE 5000
CMD ["python", "app.py"]
