# Build image
FROM ghcr.io/astral-sh/uv:0.11.19-alpine AS builder

# Switch to non-root (a group with gid=uid is automatically created)
RUN adduser -D -u 65532 nonroot
RUN mkdir /app && chown nonroot:nonroot /app
USER 65532

ENV UV_CACHE_DIR="/home/nonroot/.cache/uv"

WORKDIR /app

# Copy application
COPY pyproject.toml uv.lock ./
COPY kcwarden/ ./kcwarden
RUN touch README.md
RUN --mount=type=cache,uid=65532,gid=65532,target=$UV_CACHE_DIR uv sync --no-dev
# Build wheel
RUN uv build


# Actual image
FROM docker.io/library/python:3.14.6-alpine

# Update packages and switch to non-root
RUN apk upgrade -U && adduser -D --u 65532 nonroot
RUN mkdir /app && chown nonroot:nonroot /app
USER 65532

WORKDIR /app

ENV PIP_CACHE_DIR="/home/nonroot/.cache/pip" \
    PIP_PROGRESS_BAR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PATH="/home/nonroot/.local/bin:${PATH}"

COPY --from=builder "/app/dist/kcwarden*.whl" .

# Install kcwarden from wheel as user-global package
# hadolint ignore=DL3042
RUN --mount=type=cache,uid=65532,gid=65532,target=$PIP_CACHE_DIR pip install --user kcwarden*.whl && rm /app/kcwarden*.whl

ENTRYPOINT ["kcwarden"]
