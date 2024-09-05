---
title: Clients
---

# Client Misconfigurations

These auditors consider misconfigurations in OIDC Clients configured in Keycloak.
These OIDC clients are used by other applications to interact with Keycloak, authenticate users, obtain and exchange
access tokens, and perform other tasks.

!!! important

    As kcwarden can only audit the configuration of Keycloak, it cannot make any statements about the security of the
    *applications* that use these OIDC clients, and whether their use of the clients is secure.

## PublicClientsMustEnforcePKCE

This auditor checks if public clients (clients that cannot securely store credentials) are enforcing the use of Proof
Key for Code Exchange (PKCE). PKCE adds an additional layer of security, especially important for public clients, to
mitigate authorization code interception attacks. Its use is strongly recommended, as it protects against several types
of attacks. It should be implemented by the client, and enforced on the Keycloak server. The only allowed value is "
S256", as this is the only secure mode of PKCE.

## ConfidentialClientShouldEnforcePKCE

While PKCE is primarily recommended for public clients, this auditor verifies if confidential clients (clients that can
securely store credentials) also enforce PKCE. Enforcing PKCE for confidential clients provides an extra security
measure, safeguarding against certain attack vectors.

## ClientShouldDisableImplicitGrantFlow

This auditor identifies OIDC clients within Keycloak that have the implicit grant flow enabled. The implicit grant flow
is discouraged because it exposes the access token in the URL. This exposure can lead to vulnerabilities, such as access
token leakage or replay attacks. Instead, the "Authorization Code" flow (referred to as "Standard Flow" in Keycloak) is
recommended. The implicit flow should be disabled to prevent these security risks and ensure the confidentiality and
integrity of the access token.

## PublicClientShouldDisableDirectAccessGrants

This auditor focuses on identifying OIDC clients, specifically public clients within Keycloak, that have the direct
access grant flow enabled. The direct access grant flow, known in OAuth as the resource owner password credentials
grant, poses significant security risks by requiring clients to handle user credentials directly. This not only
increases the attack surface for credential exposure but also often conflicts with advanced authentication mechanisms
such as two-factor authentication (2FA) methods, including WebAuthN or SMS tokens. Given these considerations, the
direct access grant flow should be explicitly disabled for all clients, especially for public clients. Public clients
are particularly vulnerable as they can be used by anyone, not just the client's rightful users, making the misuse of
direct access grants a significant concern.

!!! info

    While some systems may use this flow for obtaining tokens for technical users, it's recommended to use
    Keycloak's _service accounts_ feature as a more secure and intended alternative for such use cases.

## ConfidentialClientShouldDisableDirectAccessGrants

This auditor targets confidential OIDC clients within Keycloak that have enabled the direct access grant flow. The
direct access grant flow, also known in OAuth 2.0 as the resource owner password credentials grant, poses significant
security risks. It necessitates clients to directly handle user credentials, substantially increasing the vulnerability
of these credentials to exposure outside of Keycloak's managed authentication environment. Moreover, this flow often
cannot be integrated with two-factor authentication (2FA) methods, such as WebAuthN or SMS tokens, potentially
undermining modern security practices.

While the use of direct access grants might seem less perilous for confidential clients, due to the requirement of a
client secret for interaction, the fundamental security concerns remain. The exposure of user credentials outside of a
controlled environment and the potential bypass of advanced authentication mechanisms advise against the use of this
flow for any client type, public or confidential.

!!! info

    While some systems may use this flow for obtaining tokens for technical users, it's recommended to use Keycloak's '
    service accounts' feature as a more secure and intended alternative for such use cases.

## ClientAuthenticationViaMTLSOrJWTRecommended

This auditor evaluates whether confidential OIDC clients within Keycloak are utilizing mutual TLS (mTLS) or signed JWTs
for client authentication, as opposed to the default 'shared client secret' method. Confidential clients are those that
can securely hold credentials, making them responsible for authenticating to Keycloak to access its features. While
using a shared client secret is common, it's recommended to opt for more secure authentication methods such as mTLS or
signed JWTs. These methods provide enhanced security by ensuring that client credentials are not exposed and are
authenticated in a manner that is both secure and verifiable. This recommendation aligns with best practices for
securing OAuth clients and protecting resource access. For more detailed guidance on implementing these recommended
authentication methods, refer to the Keycloak documentation. If switching to these methods is impossible in your setup,
you can silence this auditor in the configuration.

## ClientMustNotUseUnencryptedNonlocalRedirectUri

This auditor checks for OIDC clients that transmit authorization responses over unencrypted connections, a practice
strongly discouraged due to the sensitivity of the data involved, such as the OAuth Response Code. To safeguard this
data, `redirect_uri`s must be configured to use HTTPS URIs exclusively, or, in the case of native applications, a
localhost address. This measure is crucial for protecting authorization responses from potential exposure and
interception. The auditor evaluates OIDC clients with active flows utilizing `redirect_uri`s, specifically those with
standard or implicit flows enabled, ensuring they adhere to these security standards. It focuses on identifying and
reporting clients that use `http` in their redirect URIs for non-local addresses, as these present a significant
security risk. Localhost addresses (`localhost`, `127.0.0.1`, `::1`) using `http` are considered exceptions due to their
nature.

## ClientUsesCustomRedirectUriScheme

This auditor identifies OIDC clients that utilize custom protocol schemes in their `redirect_uri` configurations,
diverging from the standard `http://` or `https://`. Authorization responses, which include sensitive data such as the
OAuth Response Code, must be securely managed to prevent unauthorized exposure. The employment of custom protocols,
especially when integrating with mobile apps on smartphones (like `myapp://login`), introduces a potential security
risk.

## ClientHasUndefinedBaseDomainAndSchema

This auditor checks if OIDC clients have undefined or insufficiently specified redirect URI schemes, which cannot be
effectively audited. Redirect URIs are critical for ensuring the security of OAuth response codes and must be protected
from exposure. Ideally, the `redirect_uri` should be an HTTPS URI or, for native applications, a localhost address. This
auditor identifies clients where the redirect URI, in combination with the client's root URL, does not adequately define
the scheme used. This often indicates that a fully qualified domain name, including the scheme (
e.g., 'https://example.com/login'), is not defined for either the client root URL or the redirect URIs. To address this
issue, clients should specify clear redirect URIs with proper schemes to enhance security.

## ClientShouldNotUseWildcardRedirectURI

This auditor focuses on identifying OIDC clients within Keycloak that utilize wildcard characters in their
`redirect_uri` configurations. Authorization responses, which include sensitive data such as the OAuth Response Code,
necessitate secure handling to prevent unauthorized disclosure. The use of wildcards in redirect URIs introduces
security risks by potentially allowing responses to be redirected to unintended or malicious URLs, thus compromising the
confidentiality and integrity of the exchanged data.

The recommendation is to avoid wildcards in `redirect_uri` settings whenever possible to ensure that authorization
responses are directed to explicitly trusted and predefined locations. If the use of a wildcard is absolutely necessary
for a client's operation, it should be employed with the greatest possible specificity to limit the scope of acceptable
redirect destinations (e.g., `https://example.com/login/token/*` instead of `https://example.com/*`), thereby reducing
the attack surface for data leakage or redirection attacks.

Clients found to employ wildcards in their redirect URIs are flagged for review. Administrators are encouraged to refine
these configurations, removing or narrowing the use of wildcards, to enhance the security of OAuth flows and protect
sensitive information inherent to the authorization process. Once a client has been reviewed, further warnings for it
can be silenced using the tool configuration.

## ClientHasErroneouslyConfiguredWildcardURI

This auditor identifies clients with dangerously configured redirect URIs that potentially allow redirects to arbitrary
domains, posing a significant security risk. In OAuth, redirect URIs are crucial for directing the user-agent back to
the application with the authorization code. Keycloak mandates specifying allowed redirect URIs to prevent unauthorized
redirects. However, a configuration error like specifying a wildcard in the domain part of the redirect URI (e.g.,
`https://example.com*`) instead of after a path delimiter (e.g., `https://example.com/*`) could let an attacker specify
a malicious domain that still matches the configured pattern (e.g., `https://example.com.attacker.com/`).

## ClientWithServiceAccountAndOtherFlowEnabled

This auditor examines confidential OIDC clients that have service accounts enabled alongside other authorization flows,
such as standard, implicit, or direct access grants. Typically, confidential clients with service accounts are utilized
solely for server-to-server interactions via the service account. In these scenarios, enabling additional authorization
flows may not be necessary and could potentially increase the client's attack surface.

The recommendation is to disable any extraneous flows for clients primarily used for service account purposes. This
audit generates informational findings to highlight clients where service accounts and additional flows are
simultaneously active, prompting a review to ensure that this configuration aligns with the intended use of the client.

If a client is intentionally using both service accounts and other authorization flows for valid use cases, the finding
can be disregarded. However, we would still recommend splitting the functionality into two clients whenever possible, to
avoid the chance of misconfigurations leading to overprivileged tokens.

## UsingNonDefaultUserAttributesInClientsWithoutUserProfilesFeatureIsDangerous

This auditor identifies a critical configuration issue where Keycloak clients use custom user attributes without
enabling the User Profiles feature. Keycloak permits the addition of custom attributes to user accounts beyond the
default ones like name, email, and phone number. However, by default, users can edit their own attributes, which poses a
risk if these attributes contain sensitive information used in external systems, such as customer numbers linking
Keycloak accounts to other databases.

The use of custom user attributes without restrictions is hazardous because it allows users to alter information that
external systems rely on for important operations or access control decisions. This practice must be avoided to ensure
the integrity of the data shared across integrated systems.

To mitigate this risk, Keycloak introduced the User Profiles feature, allowing administrators to define policies that
restrict user ability to edit specific attributes. This auditor flags clients that utilize custom user attributes
without activating the User Profiles feature, signaling a potential security vulnerability. It encourages the use of the
User Profiles feature to securely manage user attributes and prevent unauthorized modifications, as detailed in
Keycloak's documentation.

!!! info
    
    The user profiles feature was an experimental feature for many versions of Keycloak that was disabled by default. It was
    enabled by default for newly created realms starting with Keycloak version 24.

## ClientWithDefaultOfflineAccessScope

TODO Check if this is correct, as offline tokens also require refresh tokens to be enabled in the client. => Check
implementation and description, make them correct and consistent.

This auditor warns against clients that include the `offline_access` scope in their default client scopes within
Keycloak. The `offline_access` scope grants the use of offline tokens, which are an extended and more potent form of
refresh tokens. Offline tokens maintain user login sessions for extended periods, often lasting several months, and are
typically utilized by native applications (e.g., mobile apps) or for server-to-server connections that require access to
a user's account in the user's absence.

While offline tokens are beneficial for certain use cases, their inclusion as a default scope for clients that do not
require such extended access poses a significant security risk. If an offline token is compromised, it could allow an
attacker to maintain unauthorized access to a user's account for an extended period, potentially bypassing regular
session expiration mechanisms.

Clients should be carefully reviewed to ensure that the use of offline tokens is genuinely necessary for their
operation. If not required, it is advisable to remove the `offline_access` scope from the default client scopes, disable
refresh tokens for the client, or adjust the configuration to mitigate the potential security risks associated with
long-lived access tokens. This auditor aims to highlight clients with potentially unnecessary default offline access to
prompt a security review and adjustment of their configuration.

## ClientWithOptionalOfflineAccessScope

TODO Check if this is correct, as offline tokens also require refresh tokens to be enabled in the client. => Check
implementation and description, make them correct and consistent.

This auditor alerts on Keycloak clients that have the `offline_access` scope set as an optional client scope. The
`offline_access` scope grants applications the ability to use offline tokens, which are enhanced versions of refresh
tokens with significantly longer lifespans. These tokens are especially useful for applications requiring prolonged
access to a user's account without active user participation, such as mobile applications or server-to-server
communications.

However, the inclusion of the `offline_access` scope, even as an optional one, raises security concerns for clients that
do not necessitate such extended access capabilities. The potential exposure of offline tokens poses a risk of long-term
unauthorized access to user accounts if these tokens are compromised.

Clients leveraging the `offline_access` scope should undergo a thorough review to ascertain the necessity of this
capability for their functionality. If the use of offline tokens is not imperative, it's recommended to either remove
this scope from the list of optional scopes, disable refresh tokens to prevent the issuance of offline tokens, or adjust
the client's configuration to ensure that the use of offline tokens aligns with the security requirements and
operational needs. This warning aims to prompt a reevaluation of the need for offline access, advocating for tighter
control and minimization of potential security vulnerabilities associated with long-lived token usage.

## ClientWithFullScopeAllowed

This auditor identifies Keycloak clients configured with the 'full scope allowed' setting enabled. In Keycloak, scopes
dictate the breadth of information and roles appended to an access token. Adhering to the principle of least privilege
is crucial in access token configuration, ensuring tokens are granted only the permissions necessary for their intended
tasks.

When 'full scope allowed' is activated for a client, Keycloak bypasses the scoped limitations and indiscriminately
includes all user roles in the token, effectively treating it as if all possible scopes were granted. This configuration
can lead to the issuance of access tokens with excessive privileges, escalating the risk of unauthorized actions if such
tokens were to be compromised.

The finding prompts a review of client configurations, encouraging administrators to specifically tailor access token
scopes to match the minimal requirements of each client. Adjusting the scope settings to disable 'full scope allowed'
mitigates the risk associated with overly permissive tokens, aligning with best practices for secure token management.
