ARG KCWARDEN_VERSION

FROM docker.io/library/python:3-alpine

# Update packages and switch to non-root
RUN apk upgrade -U && adduser -D --u 65532 nonroot
USER 65532

WORKDIR /app

ENV PIP_PROGRESS_BAR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PATH="/home/nonroot/.local/bin:${PATH}"

# Install kcwarden from wheel as user-global package
RUN pip install --no-cache-dir --user kcwarden=="${KCWARDEN_VERSION}"

ENTRYPOINT ["kcwarden"]
