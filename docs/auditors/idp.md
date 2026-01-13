---
title: IDP
---

# IDP Misconfigurations
Keycloak can be configured to delegate user authentication to an upstream Identity Provider (IDP) like Google, Azure AD, or an LDAP server.
The IDP auditors check for problems related to how this integration is configured.

!!! info

    These auditors are currently fairly bare-bones, as we haven't yet had time to read up on what specific problems may lurk in the different possible setups. If you have expertise in this area, please reach out or contribute your own auditors.

## IdentityProviderWithSignatureVerificationDisabled

This auditor warns about Identity Providers configured not to check the signatures of the upstream IDP.
Not checking the signatures of the tokens the IDP provides is dangerous, as the tokens are no longer cryptographically protected against tampering.
This may lead to an account takeover or other attacks.
We strongly recommend setting up signature checks.

The auditor supports OIDC, Keycloak OIDC, and SAML IDPs.
Provider-specific IDPs (like GitHub, GitLab, etc.) do not have an option to disable signature verification and should thus be safe by default.

## OIDCIdentityProviderWithoutPKCE

This auditor warns about OIDC Identity Providers configured within a realm that do not have the Proof Key for Code Exchange (PKCE) enabled.
PKCE is a security enhancement for the authorization code flow in OAuth 2.0 and OpenID Connect (OIDC) protocols, designed to mitigate several attack vectors, including interception and unauthorized use of authorization codes.

The recommendation is for all OIDC Identity Providers, particularly those using the `oidc` or `keycloak-oidc` provider types, to enable PKCE and set it to use the `S256` method.
This configuration is crucial for protecting against attacks on the OIDC protocol by ensuring that the _code challenge and verifier mechanism_ is securely implemented.

Identity Providers failing to enable PKCE, leaving it unset (which defaults to disabled), or incorrectly using the `plain` method instead of `S256` are flagged by this auditor.
Such configurations expose the authentication process to potential vulnerabilities, emphasizing the need for immediate corrective actions to uphold security best practices in authentication flows.

## IdentityProviderWithOneTimeSync

This auditor highlights external identity providers (IDPs) configured within Keycloak that are set to only synchronize user information from the upstream IDP at the time of the user's first login, without accepting updates on later logins.
Keycloak's default behavior imports user details (such as name and email address) from the external IDP during the user's initial login, but it does not automatically update these details based on later changes in the upstream IDP.

This setup might be by design, intending to prevent overwriting local modifications to user attributes within Keycloak.
However, if keeping user information in sync with the upstream IDP is required, the auditor recommends considering the synchronization mode `Force`.
The `Force` mode ensures that updates made to a user's information in the upstream IDP are imported into Keycloak at every login, potentially overwriting any local changes.

Entities configured without the `Force` sync mode are identified by this auditor to encourage a review of the intended behavior regarding user data synchronization.
If the current setup aligns with the organizational requirements, the finding can be ignored.
Otherwise, updating the sync mode to `Force` may be advisable to ensure consistent and up-to-date user information across systems.

## IdentityProviderWithMappersWithoutForceSyncMode

This auditor targets Keycloak configurations where external identity providers are set up with Identity Provider Mappers but are not configured to update user information from the upstream IDP beyond the initial login.
Keycloak's default behavior for Identity Provider Mappers is to import data (e.g., group assignments or roles) from the upstream IDP's access token only once, during the user's first login, without reflecting any later changes in the upstream IDP.

This configuration could lead to security issues or inconsistencies in user permissions if the upstream IDP modifies user roles, groups, or other attributes that affect access control within Keycloak-managed services.
If the use of mappers to assign static groups or roles without future updates is intentional, this finding may be disregarded.

However, if dynamic synchronization of user attributes and roles with the upstream IDP is required, it's advised to adjust the sync mode to `Force`.
This setting can be applied globally to the IDP, affecting all user data, including name and email, or specifically to relevant mappers, allowing for selective updates based on upstream changes.

This finding carries a higher severity compared to the general recommendation for enabling `Force` sync mode due to the explicit use of Identity Provider Mappers, indicating a reliance on upstream IDP data for crucial access control decisions.

## SamlIdpPostBindingResponseCheck

This auditor warns about SAML Identity Providers configured to use the **HTTP-Redirect (GET)** binding instead of the **HTTP-POST** binding for responses.
This occurs when the `Post Binding Response` setting is disabled.

When using HTTP-Redirect, the entire SAML XML payload is encoded into the URL query parameters.
This places sensitive token data into the URL, which is frequently recorded in browser history, proxy logs, and firewall logs, leading to potential data leakage.
Additionally, this configuration risks Denial of Service (DoS) issues, as the large XML payload can easily exceed browser or server URL length limits, causing login failures.

We recommend enabling `Post Binding Response` to ensure the SAML payload is sent within the HTTP body rather than the URL.

## SamlIdpValidateSignatureCheck

This auditor warns about SAML Identity Providers configured with `Validate Signature` set to `false`.
When disabled, Keycloak accepts SAML responses without verifying the digital signature of the upstream Identity Provider.

This is a critical security risk.
Without signature verification, an attacker can forge a completely fabricated SAML response or inject a malicious assertion into a valid response (known as XML Signature Wrapping or XSW).
This effectively allows an attacker to log in as any user, including administrators, without a valid password.
We strongly recommend ensuring that `Validate Signature` is enabled for all SAML providers.

## SamlIdpWantAssertionsEncryptedCheck

This auditor identifies SAML Identity Providers that do not require assertions to be encrypted (`Want Assertions Encrypted` is disabled).
When assertions are unencrypted, they are transported as Base64 strings that can be easily decoded.

Because the assertion passes through the user's browser (User Agent), any Sensitive Personally Identifiable Information (PII) contained within—such as emails, phone numbers, or group memberships—becomes visible in plain text.
This data can be exposed in browser network tabs, browser extensions, and intermediate proxy logs.
To prevent confidentiality breaches and PII leakage, we recommend enabling encryption for assertions.

## SamlIdpWantAssertionsSignedCheck

This auditor warns about SAML Identity Providers where `Want Assertions Signed` is disabled.
While the outer SAML Response envelope might be validly signed (if `Validate Signature` is on), the specific Assertion element containing the user identity is not required to be signed in this configuration.

This allows for **Assertion Substitution** attacks.
An attacker could take a valid, signed response envelope and replace the internal assertion with a forged one, bypassing authentication integrity.
For robust security, both the outer envelope and the inner assertions should be signed to prevent identity spoofing.

## SamlIdpWantAuthnRequestsSignedCheck

This auditor flags SAML Identity Providers where `Want AuthnRequests Signed` is disabled.
In this state, Keycloak sends authentication requests to the Identity Provider without a signature, causing the IdP to treat them as anonymous requests.

This configuration increases the risk of **IdP Confusion** and **Login CSRF** attacks.
It allows an attacker to craft malicious login links that force a user to authenticate against an attacker-controlled IdP or manipulate the login context, potentially leading to session hijacking.
We recommend enabling signed authentication requests to ensure the IdP can verify the origin of the login attempt.