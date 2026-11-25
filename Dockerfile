# PenLocal-lite: the harness + web UI in one image.
#
#   docker run --rm -p 8770:8770 \
#     -e OLLAMA_BASE_URL=http://host.docker.internal:11434 \
#     -e PENLOCAL_WEB_TOKEN=change-me \
#     -v ./scopes:/data/scopes -v ./penlocal-web:/data/web \
#     ghcr.io/jwklijnsma/penlocal-lite:latest
#
# The web UI is pre-built and committed (penlocal/web/static), so no Node here.
# Only a few common probes ship in the image (curl, nmap, dig, nc); bigger
# toolkits belong in `--runner docker` with the kali image from config.

FROM python:3.13-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY penlocal ./penlocal
RUN pip install --no-cache-dir build \
 && python -m build --wheel --outdir /dist \
 && python -m zipfile -l /dist/*.whl | grep -q "penlocal/web/static/app.js"

FROM python:3.13-slim
ARG VERSION=dev
LABEL org.opencontainers.image.title="penlocal-lite" \
      org.opencontainers.image.description="A local-AI penetration-testing harness — the model is only the brain." \
      org.opencontainers.image.source="https://github.com/jwklijnsma/penlocal-lite" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl nmap dnsutils netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

RUN useradd --create-home --uid 10001 penlocal \
 && mkdir -p /data/scopes /data/web \
 && chown -R penlocal:penlocal /data
USER penlocal
WORKDIR /data

ENV PYTHONUNBUFFERED=1
EXPOSE 8770
VOLUME ["/data/scopes", "/data/web"]

# Binds beyond loopback inside the container, so a token is always required
# (set PENLOCAL_WEB_TOKEN, or read the random one from the logs).
ENTRYPOINT ["penlocal"]
CMD ["serve", "--bind", "0.0.0.0", "--port", "8770", "--scopes", "/data/scopes", "--workdir", "/data/web"]
