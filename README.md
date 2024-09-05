# kcwarden - Keycloak Configuration Auditor

kcwarden checks your Keycloak configuration for common misconfigurations and security vulnerabilities.

## Installation

TBD

## Development

### Docker Image

To build a Docker image with a bundled kcwarden, you can use:

```shell
docker build -f Docker/Dockerfile -t kcwarden:0.0.1 .
```

or

```shell
buildah build -f Docker/Dockerfile -t kcwarden:0.0.1 .
```

It uses a multi-stage build to first build the application as Python wheel and afterwards install this wheel in a second
image.

### Tests

The unit tests can be run with `poetry run pytest`.

The integration tests that actually start Keycloak containers using Docker can be executed
with `poetry run pytest --integration`.
The Keycloak versions for which the tests are executed can be found in [`conftest.py`](./tests/integration/conftest.py).
It can be overridden by setting the environment variable `INTEGRATION_TEST_KEYCLOAK_VERSIONS` to a space-separated list
of Keycloak container image tags (see [quay.io](https://quay.io/repository/keycloak/keycloak?tab=tags)).

### Build the Docs

The documentation is created using [MkDocs](https://www.mkdocs.org/) and lives in the [`docs`](./docs) directory.
The dependencies for _MkDocs_ can be installed using this command: `poetry install --with docs`.
Afterward, the documentation can be built using `poetry run mkdocs build`.
The static output is then located in the `site` directory.
A development server that serves the documentation, watches for changes and automatically re-creates the site can be
spun up using `poetry run mkdocs serve`.

## Usage

Documentation will follow.