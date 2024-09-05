---
title: Realm
---

# Realm Misconfigurations
These auditors check the realm-wide settings, like token lifetimes and global security features. 

## RefreshTokensShouldBeRevokedAfterUse

This auditor warns about the configuration within Keycloak realms where refresh tokens are not invalidated after each
use. Refresh tokens are critical for maintaining active user sessions by allowing clients to request new access tokens
once the current ones expire. While this mechanism supports seamless user experiences, especially in long-lived
sessions, it introduces security risks if refresh tokens are compromised. An exposed refresh token could potentially
allow attackers to gain prolonged unauthorized access to user accounts.

To mitigate such risks, it is strongly recommended that refresh tokens be configured to rotate upon each use, thereby
invalidating the old token and issuing a new one for subsequent requests. This practice ensures that even if a refresh
token were to be leaked, it would be quickly rendered useless once used by the legitimate client.

However, it's important to note that enabling refresh token rotation may lead to complications under certain
circumstances, such as when a client issues multiple refresh tokens to the same user. This can result in unexpected
behavior and potential session disruptions. Administrators are advised to review relevant Keycloak issues and
documentation, such as the one mentioned in the auditor's reference, to understand the implications fully and configure
their realms in a manner that balances usability and security effectively.

Realms identified with refresh token revocation disabled are highlighted by this auditor to encourage a review of their
token management policies, aiming to enhance security without significantly impacting user experience.

## RefreshTokenReuseCountShouldBeZero

This auditor raises a warning about Keycloak realms configured to allow refresh tokens to be used more than once before
being revoked. Refresh tokens play a vital role in OAuth 2.0 by enabling clients to obtain new access tokens, thus
facilitating long-lived sessions without requiring the user to re-authenticate frequently. While this feature enhances
user experience, improperly managed refresh tokens can pose significant security risks, particularly if they are leaked
or exposed to malicious actors.

The recommended security practice is to rotate refresh tokens after each use, immediately invalidating the previous
token upon issuing a new one. This approach minimizes the window of opportunity for unauthorized use of a leaked token.
However, in configurations where the refresh token maximum reuse count is set to allow multiple uses, the effectiveness
of token rotation as a security measure is diminished.

Administrators should consider setting the refresh token maximum reuse count to zero, enforcing token rotation and
revocation after a single use. While mindful of potential challenges such as disruptions in user sessions, especially in
scenarios where multiple refresh tokens might be issued to the same user by the same client, it's crucial to balance
usability with security.

Realms found to permit refresh token reuse, contrary to best practices for secure token management, are flagged for
review. Administrators are encouraged to reassess their token revocation settings in light of security recommendations
and the potential implications for application behavior, aiming to enhance the overall security posture of their
Keycloak deployments.

## RealmSelfRegistrationEnabled

This auditor flags realms within Keycloak where self-registration is enabled, allowing anyone to create an account.
While self-registration can be a convenient feature for public applications or services aiming to simplify the user
onboarding process, it might not be appropriate for all contexts. Enabling self-registration can expose the system to
risks such as unauthorized access, fake account creation, and potential abuse.

The decision to allow self-registration should be carefully considered, taking into account the nature of the
application, the expected user base, and the potential security implications. In scenarios where strict control over
user access is required, or where user verification is critical, it may be advisable to disable self-registration and
opt for a more controlled account creation process.

Realms identified with self-registration enabled are brought to attention for review. Administrators should evaluate
whether this setting aligns with their security policies and operational requirements, adjusting the configuration as
necessary to safeguard against unintended or unauthorized access.

## RealmEmailVerificationDisabled

This auditor brings attention to Keycloak realms where email verification is disabled. Email verification is a crucial
feature that ensures the authenticity of the email addresses provided by users during registration. It typically
involves sending a verification link or code to the user's email address, which the user must acknowledge to complete
their registration process. This double opt-in mechanism helps in confirming that the email address is valid and
accessible by the user, adding a layer of trustworthiness to user accounts.

Disabling email verification can lead to several issues, including the inability to communicate reliably with users,
increased risk of fraudulent account creation, and potential challenges in implementing effective password recovery
mechanisms. It may also compromise the integrity of user data, especially in applications where the email address is a
critical component of the user's identity.

Realms detected with email verification turned off are highlighted for administrators to reassess this configuration
choice. Depending on the application's requirements and the level of trust needed in user-provided email addresses,
enabling email verification may be advisable to enhance security and ensure the credibility of user accounts.
