# syntax=docker/dockerfile:1
# SentinelFlow ML service (FastAPI, api.py). Python 3.14 matches the
# interpreter that produced models/pipeline.joblib.

FROM python:3.14-slim AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY requirements-docker.txt .
# CPU-only torch first, so the pinned install below finds it satisfied and never pulls CUDA wheels.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --index-url https://download.pytorch.org/whl/cpu torch==2.14.1
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements-docker.txt

FROM python:3.14-slim
# libgomp1: OpenMP runtime required by LightGBM.
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --create-home --uid 10001 sentinelflow
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
COPY --from=build /opt/venv /opt/venv
WORKDIR /app
COPY api.py config.py ./
COPY src src
COPY models/pipeline.joblib models/pipeline.joblib
COPY data/sample data/sample
# config.py creates these on import; pre-create them so the non-root user never needs write access.
RUN mkdir -p data/raw figures report
USER sentinelflow
EXPOSE 8000
# /health is always 200; only "status": "ok" means the model finished warming up (~2 min).
HEALTHCHECK --interval=15s --timeout=5s --start-period=300s --retries=5 \
  CMD python -c "import json,sys,urllib.request; sys.exit(json.load(urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)).get('status') != 'ok')"
CMD ["python", "api.py"]
