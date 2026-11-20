# syntax=docker/dockerfile:1
#
# SSC in a container (GAME_PLAN.md section 9): a hash-locked install with no
# compiler toolchain, run with `docker run --rm`. The README's Docker
# section says how to run it.

# python:3.14.10-slim-trixie, multi-arch index digest
ARG PYTHON=python:3.14.10-slim-trixie@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f

# uv 0.9.17, the version CI uses, multi-arch index digest
FROM ghcr.io/astral-sh/uv:0.9.17@sha256:5cb6b54d2bc3fe2eb9a8483db958a0b9eebf9edff68adedb369df8e7b98711a2 AS uv

FROM ${PYTHON} AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_PROJECT_ENVIRONMENT=/opt/ssc \
    UV_PYTHON_DOWNLOADS=never \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_CACHE=1
WORKDIR /src
COPY pyproject.toml uv.lock ./
# --locked installs exactly uv.lock, checking every hash in it. Dependencies
# come only as wheels: the image has no compiler, and --no-build refuses to
# try.
RUN uv sync --locked --no-dev --no-install-project --no-build
COPY README.md LICENSE ./
COPY src ./src
# Then SSC itself, built as a wheel by its pure-Python backend.
RUN uv sync --locked --no-dev --no-editable

FROM ${PYTHON}
ARG SSC_VERSION=dev
# /ssc holds the vault and settings; /work is where files are encrypted.
# Without a keychain in the container, SSC asks for the master password
# (VAULT.md section 2).
RUN useradd --uid 1000 --user-group --no-create-home --home-dir /ssc \
        --shell /usr/sbin/nologin ssc \
    && mkdir -m 700 /ssc \
    && mkdir /work \
    && chown ssc:ssc /ssc /work
COPY --from=build /opt/ssc /opt/ssc
ENV PATH=/opt/ssc/bin:$PATH \
    XDG_DATA_HOME=/ssc/data \
    XDG_CONFIG_HOME=/ssc/config \
    PYTHONDONTWRITEBYTECODE=1
USER ssc
WORKDIR /work
VOLUME ["/ssc"]
ENTRYPOINT ["ssc"]

LABEL org.opencontainers.image.title="secure-string-cipher" \
      org.opencontainers.image.description="Local file encryption where every file carries its own access rules" \
      org.opencontainers.image.source="https://github.com/TheRedTower/secure-string-cipher" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${SSC_VERSION}" \
      org.opencontainers.image.base.name="docker.io/library/python:3.14.10-slim-trixie"
