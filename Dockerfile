# Network IDS: API + dashboard image. Models are NOT baked in: mount them read-only at /app/models.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 IDS_VAR_DIR=/app/var

RUN useradd --system --uid 10001 --home /app ids
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY src ./src
COPY api ./api
COPY dashboard ./dashboard
COPY .streamlit ./.streamlit
RUN mkdir -p /app/var /app/models /app/data/processed && chown -R ids:ids /app/var

USER ids
EXPOSE 8000 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)" || exit 1

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
