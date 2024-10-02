---
title: Installation
---

# How to install

There are two ways to install _kcwarden_:

## Python

You can install _kcwarden_ from PyPI:

```shell
pip install kcwarden
```

You might want to use [pipx](https://github.com/pypa/pipx) to automatically encapsulate the dependencies of _kcwarden_ in a virtual environment.

## Docker

Alternatively, _kcwarden_ is provided as a Docker image and can be executed in this way:

```shell
docker run --rm ghcr.io/iteratec/kcwarden:latest
```

Using this way, you need to replace the `kcwarden` call with the Docker command above.
