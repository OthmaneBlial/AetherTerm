# The server listens on loopback; run with Linux host networking and a trusted
# same-host TLS proxy only after the remote deployment gate has been validated.
FROM python:3.13-slim-bookworm AS builder
WORKDIR /src
COPY pyproject.toml README.md LICENSE MANIFEST.in ./
COPY requirements-runtime.lock ./
COPY server ./server
COPY client ./client
COPY web ./web
RUN python -m pip download --no-cache-dir --only-binary=:all: --require-hashes \
      --dest /wheels -r requirements-runtime.lock \
    && python -m pip wheel --no-cache-dir --no-deps --wheel-dir /wheels .

FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/data \
    AETHERTERM_OPERATOR_FILE=/data/operator.json \
    AETHERTERM_AGENTS_FILE=/data/agents.json
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels aetherterm \
    && rm -rf /wheels \
    && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin aetherterm \
    && mkdir /data && chown aetherterm:aetherterm /data
USER aetherterm
WORKDIR /data
ENTRYPOINT ["aetherterm-server"]
