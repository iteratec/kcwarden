---
title: Introduction
---

# Introduction

kcwarden comes with a number of pre-built detection rules that can detect common Keycloak misconfigurations.
We call these _auditors_, and each auditor checks for one specific problem.
There are auditors for OAuth clients, scopes, upstream Identity Provider (IDP) configurations, and realm settings. 
The auditors are based on a combination of
the [OAuth 2.0 Security Best Current Practices RFC Draft (Version 24)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-24),
and additional, Keycloak-specific checks.

## Running Auditors

All auditors are run by default when running kcwarden. However, you can also limit the set of auditors using a CLI flag, and control which severity of findings you want to have reported. See [usage](../usage.md) for more details.

## Coverage

!!! danger

    Please note that, as kcwarden is currently in beta, it **does not yet cover all aspects of Keycloak configuration and operation**.
    There are parts of the configuration that have only very few checks associated with them, and some features have no coverage at all.

At the moment, the following parts of the configuration have fairly good coverage with security checks:

- OpenID Connect Clients
- Service Accounts

The following parts have some coverage, but may still have some gaps:

- Realm settings
- Scopes
- Protocol Mappers

The following areas are only lightly covered:

- IDPs (only some sanity checks on OIDC IDPs)

The following areas aren't covered at all:

- Non-OIDC clients (e.g., SAML)
- Non-OIDC IDPs (LDAP / SAML) 
- User Federation
- IDP Mappers
- Authentication Flows
- Required Actions
- Anything related to the implementation of the applications working with the clients (out of scope)

We would be grateful for input on which checks you would like to see - ideally with a description of what exactly to check for, what a good and an insecure configuration would look like, and what the impact of the misconfiguration would be.
Feel free to open an issue in our GitHub and we'll be happy to add it to the code.

## Silencing Findings

If you run kcwarden for the first time on a Keycloak configuration, chances are that you will receive a large number of
findings.
kcwarden tends to err on the side of reporting too much instead of too little, so there are likely to be some findings
that you don't want to act on because you have good reasons to configure the system in this way, even though it may not
be 100% compliant with official recommendations.
In these cases, you can ignore specific findings or entire auditors to prevent kcwarden from reporting them again.

### Ignoring a Specific Finding

To ignore a specific finding, you can [create a config file](../usage.md#generate-config-template) and add the specific entity that was flagged to the allowlist. For example, if you have a client `mobile_app` that is used by a native mobile application that requires the use of offline access tokens, you can silence the warning about the use of these tokens for this specific client with the following configuration entry:

```yaml
auditors:
- auditor: ClientWithOptionalOfflineAccessScope
  allowed:
  - mobile_app  # Allow offline access for mobile app client
```

### Ignoring Multiple Findings

In some cases, you may want to ignore a finding for a large set of clients, or maybe even for all clients. In this case, you can use the built-in regular expression support of the allowlist feature:

```yaml
auditors:
- auditor: ClientWithOptionalOfflineAccessScope
  allowed:
  - app_.*  # Allow access for app_ios, app_android, app_firetv, ...
- auditor: ClientAuthenticationViaMTLSOrJWTRecommended
  allowed:
  # Due to the use of legacy software, we need to allow client-secret 
  # auth for the forseeable future. Allowlist all clients.
  - .*  
```