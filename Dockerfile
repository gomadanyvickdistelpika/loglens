# LogLens - Linux / cloud image.  Build:  docker build -t loglens .
# Run:   docker run -p 8765:8765 -v /path/to/bundles:/data:ro -e LVX_ROOTS=/data loglens
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends poppler-utils \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 lvx
WORKDIR /app
COPY lvx /app/lvx
USER lvx
ENV LVX_HOST=0.0.0.0 LVX_PORT=8765 PYTHONUNBUFFERED=1
# Set LVX_TOKEN to require a bearer token; set LVX_ROOTS to restrict server-path opening.
EXPOSE 8765
HEALTHCHECK --interval=30s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8765/api/health')"
CMD ["python", "-m", "lvx", "serve"]
