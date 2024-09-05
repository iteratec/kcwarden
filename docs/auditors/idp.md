---
title: IDP
---

# IDP Misconfigurations
Keycloak can be configured to delegate user authentication to an upstream Identity Provider (IDP) like Google, Azure AD, or an LDAP server. The IDP auditors check for problems related to how this integration is configured.

!!! info

    These auditors are currently fairly bare-bones, as we haven't yet had time to read up on what specific problems may lurk in the different possible setups. If you have expertise in this area, please reach out or contribute your own auditors.

## OIDCIdentityProviderWithoutPKCE

This auditor warns about OIDC Identity Providers configured within a realm that do not have the Proof Key for Code
Exchange (PKCE) enabled. PKCE is a security enhancement for the authorization code flow in OAuth 2.0 and OpenID
Connect (OIDC) protocols, designed to mitigate several attack vectors, including interception and unauthorized use of
authorization codes.

The recommendation is for all OIDC Identity Providers, particularly those utilizing the "oidc" or "keycloak-oidc"
provider types, to enable PKCE and set it to use the "S256" method. This configuration is crucial for protecting against
attacks on the OIDC protocol by ensuring that the code challenge and verifier mechanism is securely implemented.

Identity Providers failing to enable PKCE, leaving it unset (which defaults to disabled), or incorrectly using the "
plain" method instead of "S256" are flagged by this auditor. Such configurations expose the authentication process to
potential vulnerabilities, emphasizing the need for immediate corrective actions to uphold security best practices in
authentication flows.

## IdentityProviderWithOneTimeSync

This auditor highlights external identity providers (IDPs) configured within Keycloak that are set to only synchronize
user information from the upstream IDP at the time of the user's first login, without accepting updates on subsequent
logins. Keycloak's default behavior imports user details (such as name and email address) from the external IDP during
the user's initial login, but it does not automatically update these details based on subsequent changes in the upstream
IDP.

This setup might be by design, intending to prevent overwriting local modifications to user attributes within Keycloak.
However, if keeping user information in sync with the upstream IDP is required, the auditor recommends considering the
synchronization mode 'Force'. The 'Force' mode ensures that updates made to a user's information in the upstream IDP are
imported into Keycloak at every login, potentially overwriting any local changes.

Entities configured without the 'Force' sync mode are identified by this auditor to encourage a review of the intended
behavior regarding user data synchronization. If the current setup aligns with the organizational requirements, the
finding can be ignored. Otherwise, updating the sync mode to 'Force' may be advisable to ensure consistent and
up-to-date user information across systems.

## IdentityProviderWithMappersWithoutForceSyncMode

This auditor targets Keycloak configurations where external identity providers are set up with Identity Provider Mappers
but are not configured to update user information from the upstream IDP beyond the initial login. Keycloak's default
behavior for Identity Provider Mappers is to import data (e.g., group assignments or roles) from the upstream IDP's
access token only once, during the user's first login, without reflecting any subsequent changes in the upstream IDP.

This configuration could lead to security issues or inconsistencies in user permissions if the upstream IDP modifies
user roles, groups, or other attributes that affect access control within Keycloak-managed services. If the use of
mappers to assign static groups or roles without future updates is intentional, this finding may be disregarded.

However, if dynamic synchronization of user attributes and roles with the upstream IDP is required, it's advised to
adjust the sync mode to 'Force'. This setting can be applied globally to the IDP, affecting all user data, including
name and email, or specifically to relevant mappers, allowing for selective updates based on upstream changes.

This finding carries a higher severity compared to the general recommendation for enabling 'Force' sync mode due to the
explicit use of Identity Provider Mappers, indicating a reliance on upstream IDP data for crucial access control
decisions.