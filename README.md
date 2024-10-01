# kcwarden - Keycloak Configuration Auditor

![Python](https://img.shields.io/pypi/pyversions/kcwarden.svg)
[![PyPI version](https://img.shields.io/pypi/v/kcwarden.svg)](https://pypi.python.org/pypi/kcwarden)
[![Mkdocs](https://img.shields.io/badge/doc-mkdocs-845ed7.svg)](https://iteratec.github.io/kcwarden)
[![GitHub discussions](https://img.shields.io/badge/discuss-online-845ef7)](https://github.com/iteratec/kcwarden/discussions)
[![Downloads](https://pepy.tech/badge/kcwarden)](https://pepy.tech/project/kcwarden)
[![GitHub stars](https://img.shields.io/github/stars/iteratec/kcwarden?style=flat)](https://github.com/iteratec/kcwarden/stargazers)

[![last release status](https://github.com/iteratec/kcwarden/actions/workflows/publish.yaml/badge.svg)](https://github.com/iteratec/kcwarden/actions/workflows/publish.yaml)

**[kcwarden](https://iteratec.github.io/kcwarden/) checks your Keycloak configuration for common misconfigurations and security vulnerabilities.**

## 🚀 Getting started

Install it using Python:

```shell
pip install kcwarden
```

For details and other methods, see our [documentation](https://iteratec.github.io/kcwarden/installation/).

## ▶️ Usage

Download your Keycloak's config:

```shell
kcwarden download --realm $REALM --user admin --output config.json $KEYCLOAK_BASE_URL
```

and run the checks against it:

```shell
kcwarden audit config.json
```

For more information, see the [documentation on the project website](https://iteratec.github.io/kcwarden/).
