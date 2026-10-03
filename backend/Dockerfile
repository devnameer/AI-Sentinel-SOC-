# Django API + agents + ML. Build from the REPOSITORY ROOT (it needs models/ and data/):
#   docker build -f backend/Dockerfile -t sentinel-backend .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# libgomp1: OpenMP runtime used by scikit-learn and CatBoost
RUN apt-get update \
 && apt-get install -y --no-install-recommends libgomp1 \
 && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt backend/requirements.txt
RUN pip install -r backend/requirements.txt

COPY backend backend
COPY models models
COPY data/datasets data/datasets
COPY scripts scripts

# Run as an unprivileged user; only data/runtime (a volume) is writable.
RUN useradd --create-home --uid 1000 soc \
 && mkdir -p data/runtime \
 && chown -R soc:soc data/runtime
USER soc

WORKDIR /app/backend
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/system/ping/', timeout=4)"

# ONE worker on purpose: models, the Q-table, the live-replay thread and the runtime LLM switch
# are kept in process memory. Threads give concurrency; long timeout covers slow CPU LLM calls.
CMD ["sh", "-c", "python manage.py migrate --noinput && exec gunicorn soc_platform.wsgi:application --bind 0.0.0.0:8000 --workers 1 --threads 8 --timeout 300 --access-logfile -"]
