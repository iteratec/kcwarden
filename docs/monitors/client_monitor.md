---
title: Clients
---

# Client Monitors

You can use client monitors to keep an eye on the configuration of specific OIDC clients. Please be sure that you have read our [general introduction to Monitors](index.md) to understand the context of this feature.


## ClientWithSensitiveRole

Many applications rely on the roles mapped into an access token to grant or reject access to specific functions.
This makes it important to ensure that roles are only added to the tokens you expect.
For a role to be added to an access token, several things have to be true:

- The authenticating user or service account must have the role assigned (directly, through a composite role, or through group membership)
- The client must have a scope assigned that includes the relevant role, OR the client must have "full scope allowed" set
- The client must have a way of mapping roles into the access token (through a role mapper, assigned directly to the client or assigned indirectly through scopes)

If all of these conditions are true, a role will be added to the access token.
Checking this manually is time-consuming and error-prone, so this monitor encapsulates this logic.
If you have several clients that are authenticating users, and only one of them should be able to map a specific role into the access token, use this monitor to control which clients can map this role.
For example, if you are interested in the realm role `org_admin`, the configuration could look like this:

```yaml
monitors:
- monitor: ClientWithSensitiveRole
  config:
  - role: "org_admin"
    severity: Critical
    role-client: realm   # it's a realm-wide role, not a client-specific role
    allowed:
    - admin_backend
    note: org_admin controls access to org management. Only the client admin_backend should have access to it.
```

The field `role` and `allowed` fields support the Python RegEx syntax, so you can match all roles beginning with `org_` by writing `^org_.*` as the role name you want to monitor, and similarly use wildcards in your allowlists.
If you want to match a realm role (i.e., a role defined on the level of the Keycloak realm), put "realm" as the role-client.
If you are using a client role (i.e., a role defined on the level of an individual client, like the built-in realm-management roles), put the name of the client that defines the role in the field.
The role-client field does not support regular expressions and is case-sensitive.

!!! info

    If you want to create comprehensive monitoring for a single role, we recommend combining this monitor with the [GroupWithSensitiveRole](group_monitor.md#groupwithsensitiverole) and [ServiceAccountWithSensitiveRole](service_account_monitor.md#serviceaccountwithsensitiverole) monitors to achieve more comprehensive coverage.


## ClientWithSensitiveScope

Some applications differentiate which features a user can use based on the scopes included in their access token.
Thus, for sensitive scopes, it is important that you keep an eye on which clients can generate tokens that include these scopes.
In general, to generate an access token containing a specific scope, one of the following conditions must be met:

- The client contains the scope as a default scope, or
- The client contains the scope as an optional scope, and the request to generate the access token explicitly requests this scope

!!! info

    Additionally, in order for the scope name to appear in the token, the scope must have the option "include in token scope" enabled - however, this auditor does not enforce this setting, as you may want to monitor scope assignments for other reasons than their inclusion into the access token (e.g., because they are used to include additional mappers or other features), and enforcing this limitation would lead to false negatives.

In order to monitor a specific scope, you can add the following to your config file:

```yaml
monitors:
- monitor: ClientWithSensitiveScope
  config:
  - scope: interesting_scope
    allowed:
    - allowed_client
    note: This scope should only be assigned to allowed_client
    severity: Medium
```
