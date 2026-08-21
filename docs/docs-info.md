While developing the connector, please fill out this form. This information is needed to write docs and to help other users set up the connector.

## Connector capabilities

1. What resources does the connector sync?

    - Users (`posixAccount`)
    - Groups (`ipaUserGroup`)
    - Roles (`groupOfNames` under the role search DN)
    - Hosts (`ipaHost`)
    - Host groups (`ipaHostGroup`)

    HBAC rules (`ipaHBACRule`) are read but are not synced as their own resource type. They are the source of the entitlements that appear on hosts and host groups.

2. Can the connector provision any resources? If so, which ones?

    Yes, partially.

    | Resource | Grant | Revoke | Create | Delete |
    | :--- | :--- | :--- | :--- | :--- |
    | Groups | ✅ `member` and `manager`, by adding the principal's DN to `member` / `memberManager` | ✅ removes the DN from that attribute | - | - |
    | Roles | ✅ `member`, accepting users, groups, hosts and host groups as principals | ✅ | - | - |
    | Users | - | - | - | ✅ deletes the directory entry |
    | Hosts | - | - | - | - |
    | Host groups | - | - | - | - |

    Account creation is not implemented. Account deprovisioning is a hard delete of the entry, not a disable.

## Connector credentials

1. What credentials or information are needed to set up the connector? (For example, API key, client ID and secret, domain, etc.)

    - **URL**: the FreeIPA server address, `ldap:` or `ldaps:` scheme, optional port (for example `ldaps://ipa.example.com:636`)
    - **Bind DN**: the full distinguished name of the account the connector binds as (for example `uid=c1-service,cn=users,cn=accounts,dc=example,dc=com`)
    - **Password**: that account's password
    - **Base DN**: the distinguished name the connector searches under (for example `dc=example,dc=com`)

2. For each item in the list above:

    * How does a user create or look up that credential or info?

      * **URL**: the hostname of the IPA server the customer already administers. Port 389 for `ldap:`, 636 for `ldaps:`.
      * **Bind DN**: created in FreeIPA like any other user — `ipa user-add`, or Identity → Users in the Admin UI. The DN is the entry's path; for a user created in the default container it is `uid=<login>,cn=users,cn=accounts,<base DN>`.
      * **Password**: set when the account is created, or with `ipa passwd`.
      * **Base DN**: derived from the IPA realm. A realm of `EXAMPLE.COM` gives a base DN of `dc=example,dc=com`.

    * Does the credential need any specific scopes or permissions? If so, list them here.

      LDAP has no scope model, so access is granted through directory permissions rather than scopes. The bind account needs read access to the containers holding users, groups, roles, hosts, host groups and HBAC rules.

    * If applicable: Is the list of scopes or permissions different to sync (read) versus provision (read-write)? If so, list the difference here.

      * **Sync (read-only)**: read access over the base DN subtree. Reading `krbLastSuccessfulAuth` for last login also requires that operational attributes are available; the `--disable-operational-attrs` flag turns that off, along with created-at.
      * **Provisioning (read-write)**: additionally, write access to the `member` and `memberManager` attributes on the groups and roles C1 should manage, and delete permission on user entries if account deprovisioning is wanted.

    * What level of access or permissions does the user need in order to create the credentials?

      An account that can create users and grant directory permissions — in practice a member of `admins`, or a role holding the *User Administrator* and *Host Administrator* privileges.

## Notes for reviewers

- **Deployment shape.** This connector speaks LDAP to a server that is usually internal-only, so most customers run it self-hosted rather than cloud-hosted. A cloud-hosted connector would need network reach from C1's infrastructure to the IPA server.
- **The `--domain` and `--user-dn` flags are deprecated** and hidden from the generated config schema. `--url` replaces `--domain`; `--bind-dn` replaces `--user-dn`. New setups should never need them.
- **Wildcard HBAC rules.** A rule whose `hostCategory` or `userCategory` is `all` — including the `allow_all` rule FreeIPA ships enabled — is modelled as a grant against a single virtual **Any host** or **Anyone** resource rather than being expanded across every host. This keeps a default IPA install from producing a grant per host, but it does mean the wildcard is visible in C1 as one row rather than as broad access.
- **No plan or tier gating.** FreeIPA is open source and Red Hat Identity Management ships with RHEL; there are no paid tiers that hide resource types from this connector.
