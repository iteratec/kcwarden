---
title: Development
---

# Development

kcwarden uses [Poetry](https://python-poetry.org/) for dependency management and bundling.
You might want to use [pipx](https://github.com/pypa/pipx) to install Poetry.

After Poetry is set up, you can install all dependencies (including development dependencies) using `poetry install`.

If the package is build, the version is determined by the git tag.
Thus, a Poetry plugin is used that must be installed using `poetry self add "poetry-dynamic-versioning[plugin]`.
It also requires that you have git installed on your system.

## Linting and Formatting

`ruff` is used as linter and code formatter.
It can be executed using `poetry run ruff . --fix` for linting with automatic fixes and `poetry run ruff format .` for formatting.

The pipeline only succeeds if the code is formatted and there are no linting issues.

## Tests

The unit tests can be run with `poetry run pytest`.

The integration tests that actually start Keycloak containers using Docker can be executed with `poetry run pytest --integration`.
The Keycloak versions for which the tests are executed can be found in [`conftest.py`](https://iteratec.github.io/kcwarden/tests/integration/conftest.py).
It can be overridden by setting the environment variable `INTEGRATION_TEST_KEYCLOAK_VERSIONS` to a space-separated list of Keycloak container image tags (see [quay.io](https://quay.io/repository/keycloak/keycloak?tab=tags)).

## Pre-commit Hooks

Linting, formatting, and tests can be automatically run before commiting/pushing.
To install the git hooks, run `poetry run pre-commit install`.

## Docker Image

To build a Docker image with a bundled kcwarden from the local repository, you can use:

```shell
docker build -f Docker/dev.Dockerfile -t kcwarden:latest .
```

or

```shell
buildah build -f Docker/dev.Dockerfile -t kcwarden:latest .
```

It uses a multi-stage build to first build the application as Python wheel and afterward install this wheel in a second image.

## Release

kcwarden is released as Python package on [PyPI](https://pypi.org/project/kcwarden/) and as Docker image on [ghcr.io](https://github.com/iteratec/kcwarden/pkgs/container/kcwarden).

For publishing these artifacts, a release is created on GitHub and then a GitHub workflow creates and publishes the packages.

## Build the Docs

The documentation is created using [MkDocs](https://www.mkdocs.org/) and lives in the `docs` directory.
The dependencies for _MkDocs_ can be installed using this command: `poetry install --with docs`.
Afterward, the documentation can be built using `poetry run mkdocs build`.
The static output is then located in the `site` directory.
A development server that serves the documentation, watches for changes and automatically re-creates the site can be spun up using `poetry run mkdocs serve`.
