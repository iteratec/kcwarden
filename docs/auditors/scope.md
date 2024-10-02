---
title: Scope
---

# Scope Misconfigurations
These auditors check the configuration of the OIDC scopes configured in Keycloak.

!!! info

    These auditors are currently fairly bare-bones, as we haven't yet had time to read up on what specific problems may lurk in the different possible setups. If you have expertise in this area, please reach out or contribute your own auditors.

## UsingNonDefaultUserAttributesInScopesWithoutUserProfilesFeatureIsDangerous

This auditor focuses on the usage of non-default user attributes in client scopes within Keycloak, particularly when the server does not have the User Profiles feature enabled.
Keycloak permits the assignment of custom attributes to user profiles beyond the standard attributes (e.g., name, email, and phone number).
However, without proper restrictions, users might modify their own attributes via the user console, potentially affecting the reliability of these attributes in external systems.
For instance, a customer number stored as a custom attribute could be altered, disrupting the linkage between a Keycloak account and a customer database.

The danger arises when these custom attributes are employed in client scopes without enabling Keycloak's experimental User Profiles feature.
This feature allows administrators to define policies controlling attribute editability, thus preventing users from altering sensitive information.

This auditor raises a flag when client scopes use custom user attributes, and the realm lacks the User Profiles feature activation.
It suggests reviewing the use of these attributes within scopes, advocating for the activation of User Profiles and the establishment of attribute editing policies to safeguard sensitive information.

The finding is particularly severe because the lack of restriction could lead to security vulnerabilities, where critical information stored in user attributes could be tampered with by the users themselves or exploited by attackers.
Implementing the User Profiles feature and adjusting scope configurations accordingly is recommended to ensure data integrity and security.
