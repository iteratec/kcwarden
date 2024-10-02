---
title: Group
---

# Group Monitor
You can use group monitors to detect if groups have incorrect configurations.
Please be sure that you have read our [general introduction to Monitors](index.md) to understand the context of this feature.

## GroupWithSensitiveRole
This monitor allows you to check if a group has unexpected role assignments.
For example, if you have a specific role that should only be assigned to one group, you can monitor this restriction using a configuration like the following:

```yaml
monitors:
- monitor: GroupWithSensitiveRole
  config:
  - role: "org_admin"
    severity: Critical
    role-client: realm
    allowed:
      - /OrgAdm
    note: org_admin controls access to org management. Only the group /OrgAdm should have it.
```

This monitor will consider both roles assigned directly to a group, and roles inherited from parent groups.
It will also detect if a composite role containing the monitored role is assigned to the group.
The `role` and `allowed` fields support regular expressions, the `role-client` field does not.
Set the `role-client` field to `realm` when monitoring realm roles, or to the name of the client if it is a client role.

!!! info

    If you want to create comprehensive monitoring for a single role, we recommend combining this monitor with the [ClientWithSensitiveRole](client_monitor.md#clientwithsensitiverole) and [ServiceAccountWithSensitiveRole](service_account_monitor.md#serviceaccountwithsensitiverole) monitors to achieve more comprehensive coverage.
