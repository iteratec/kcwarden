# Build image
FROM docker.io/library/python:3-alpine as builder

# Switch to non-root (a group with gid=uid is automatically created)
RUN adduser -D -u 65532 nonroot
USER 65532

ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1 \
    POETRY_CACHE_DIR="/home/nonroot/.cache/poetry" \
    PIP_CACHE_DIR="/home/nonroot/.cache/pip" \
    PIP_PROGRESS_BAR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PATH="/home/nonroot/.local/bin:${PATH}"

# Install poetry with cache
# hadolint ignore=DL3042
RUN --mount=type=cache,uid=65532,gid=65532,target=$PIP_CACHE_DIR pip install --user poetry==1.8.2

WORKDIR /app

# Copy application
COPY pyproject.toml poetry.lock ./
COPY kcwarden/ ./kcwarden
RUN touch README.md
RUN --mount=type=cache,uid=65532,gid=65532,target=$POETRY_CACHE_DIR poetry install --without dev --no-root
# Build wheel
RUN poetry build


# Actual image
FROM docker.io/library/python:3-alpine

# Update packages and switch to non-root
RUN apk upgrade -U && adduser -D --u 65532 nonroot
USER 65532

WORKDIR /app

ENV PIP_CACHE_DIR="/home/nonroot/.cache/pip" \
    PIP_PROGRESS_BAR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PATH="/home/nonroot/.local/bin:${PATH}"

COPY --from=builder /app/dist/kcwarden*.whl .

# Install kcwarden from wheel as user-global package
# hadolint ignore=DL3042
RUN --mount=type=cache,uid=65532,gid=65532,target=$PIP_CACHE_DIR pip install --user kcwarden*.whl && rm /app/kcwarden*.whl

ENTRYPOINT ["kcwarden"]
