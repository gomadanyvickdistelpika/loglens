# LogLens - Linux / cloud image.  Build:  docker build -t loglens .
# Run:   docker run -p 8765:8765 -v /path/to/bundles:/data:ro -e LVX_ROOTS=/data loglens
FROM python:3.12-slim
# poppler-utils is only needed to import PDF reports; the build continues without it if apt is unreachable
# (LogLens then reports a clear 'install pdftotext' error when a PDF is opened).
RUN (apt-get update && apt-get install -y --no-install-recommends poppler-utils || echo "WARN: poppler-utils not installed") \
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
