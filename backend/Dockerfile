# SentinelQA API image (development).
# Phase 10 adds a slimmer multi-stage production image.
FROM python:3.12.10-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Run as an unprivileged user, never as root.
RUN useradd --create-home --uid 10001 appuser

# Install dependencies first so Docker can reuse this layer when only code changes.
COPY requirements.txt requirements-dev.txt ./
RUN pip install -r requirements.txt -r requirements-dev.txt

COPY . .

USER appuser
EXPOSE 8000

# Apply database migrations, then start the API.
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
