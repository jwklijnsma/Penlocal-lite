# Docker image

The `docker` workflow builds `ghcr.io/jwklijnsma/penlocal-lite` (amd64 + arm64)
and pushes it to GHCR: `:main` and `:sha-…` on every push to `main`, and
`:X.Y.Z`, `:X.Y`, `:X`, `:latest` for each release. Pull requests only build.

```bash
docker run --rm -p 8770:8770 \
  -e OLLAMA_BASE_URL=http://host.docker.internal:11434 \
  -e PENLOCAL_WEB_TOKEN=change-me \
  -v ./scopes:/data/scopes -v ./penlocal-web:/data/web \
  ghcr.io/jwklijnsma/penlocal-lite:latest
# CLI instead of the UI:
docker run --rm ghcr.io/jwklijnsma/penlocal-lite:latest demo
```

The container serves the UI on `0.0.0.0:8770`, so the access token is always on.
It ships only `curl`, `nmap`, `dig` and `nc`; for the full toolkit use
`--runner docker` with the Kali image from the config.
