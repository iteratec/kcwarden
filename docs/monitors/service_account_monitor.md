---
title: Service Accounts
---

# Service Account Monitors
Service accounts are often used to authenticate machine-to-machine communication using Keycloak.
Thus, they are often set up with fairly powerful roles and can generate highly privileged tokens.
Service Account Monitors allow you to keep an eye on their configuration, to detect overprivileged or misconfigured service accounts.
Please be sure that you have read our [general introduction to Monitors](index.md) to understand the context of this feature.

## ServiceAccountWithSensitiveRole
In a large deployment with many roles and service accounts, configuration drift can be a real concern.
Service accounts may have roles assigned to them that should have been removed months ago, or that were assigned in error.
For certain roles, this can pose a threat to the security of the system.

This Monitor allows you to keep an eye on the most sensitive roles.
You can define a role and a list of service accounts you expect to have access to this role, and the monitor will raise a finding when additional service accounts are assigned this role.

!!! info

    The monitor will not notify you if an expected service account *loses* the role. If this would be a useful feature in your environment, please open an issue on our GitHub repo to let us know.

A configuration may look something like this:

```yaml
- monitor: ServiceAccountWithSensitiveRole
  config:
  - role: ring_bearer
    role-client: realm
    severity: Critical
    allowed:
    - service-account-frodo  # prefix client name with "service-account-" here
    note: Only frodo should be allowed to carry the One Ring.
```

The `role` field supports regular expressions, allowing you to capture multiple roles with a single monitor rule, as does the list of `allowed` service accounts.
When matching realm roles, put `realm` as the `role-client`.
When matching client roles (e.g., the `manage-users` role of the `realm-management` client, which gives access to the user management features), put the name of the client that defines the roles into that field.

This monitor will detect direct role assignments, assignments via composite roles (where the monitored role is part of a composite role, which is then assigned to the service account), and assignments via groups.
If you are aware of other ways to assign roles to service accounts, let us know and we will add them as well.

!!! info

    If you want to create comprehensive monitoring for a single role, we recommend combining this monitor with the [ClientWithSensitiveRole](client_monitor.md#clientwithsensitiverole) and [GroupWithSensitiveRole](group_monitor.md#groupwithsensitiverole) monitors to achieve more comprehensive coverage.


## ServiceAccountWithGroup

Service accounts are represented as a special type of user in Keycloak.
This user can be assigned roles, but also also be added to groups and inherit roles and other settings that way.
Thus, it can be useful to monitor the group assignments of service accounts as well.

```yaml
- monitor: ServiceAccountWithGroup
  config:
  - group: "/admin"  # Use the group path, which starts with a slash
    severity: Medium
    allowed:
    - service-account-housekeeping
    allow_no_group: true
    note: The housekeeping service account should be the only account with this group.
```

If your policy is that all service accounts must be assigned to a specific group and no other, you can use the `allow_no_group` option:

```yaml
- monitor: ServiceAccountWithGroup
  config:
  - group: "/(?!ServiceAccount).*"
    severity: Medium
    allowed: []
    allow_no_group: false
    note: Service Accounts should be in the /ServiceAccount group, and no other group.
```

As you can see, the `group` field (like the `allowed` field) supports regular expressions as well.
Where necessary, you can also directly address subgroups by using their group path, i.e., `/group/subgroup`.
