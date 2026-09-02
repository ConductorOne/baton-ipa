# `baton-ipa` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-ipa.svg)](https://pkg.go.dev/github.com/conductorone/baton-ipa) ![main ci](https://github.com/conductorone/baton-ipa/actions/workflows/main.yaml/badge.svg)

`baton-ipa` is a connector for FreeIPA and Red Hat Identity Management, built using the [Baton SDK](https://github.com/conductorone/baton-sdk). It speaks LDAP to the IPA directory to sync users, groups, roles, hosts and host groups, and reads HBAC rules to derive host access.

Check out [Baton](https://github.com/conductorone/baton) to learn more about the project in general.

## Credentials

The connector binds to the IPA directory over LDAP. You need the distinguished name and password of an account that can read the directory — for example `uid=c1-service,cn=users,cn=accounts,dc=example,dc=com`. To provision access, that account also needs write access to the `member` and `memberManager` attributes on the groups and roles it manages.

# Getting Started

_See [docs/connector.mdx](./docs/connector.mdx) for the source for the published, customer-facing setup walkthrough, including how to configure the connector from ConductorOne. It's written in Mintlify's format and won't render fully on GitHub — see it live on the ConductorOne docs site once published._

## Installing

The latest release is available from the [`baton-ipa` Github releases page](https://github.com/ConductorOne/baton-ipa/releases).

Pre-built container images compatible with Docker and other container runtimes are [published to GHCR](https://github.com/ConductorOne/baton-ipa/pkgs/container/baton-ipa):
```
docker pull ghcr.io/conductorone/baton-ipa:latest
```

Additionally for testing on workstations, `baton-ipa` can be installed from Homebrew:
```
brew install conductorone/baton/baton conductorone/baton/baton-ipa
```

## Common Configuration Options

| CLI Flag | Environment Variable | Explaination |
|----------|----------|----------|
| `--bind-dn` | `BATON_BIND_DN` | **required** Username to bind to the LDAP server with, for example: `cn=baton-service-account,ou=users,dc=baton,dc=example,dc=com` |
| `--password` | `BATON_PASSWORD` | **optional**  Password to bind to the LDAP server with.  If unset, an unathenticated bind is attempted. |
| `--url` | `BATON_URL` | **required** URL to the LDAP server. Can be either `ldap:` or `ldaps:` schemes, sets the hostname, and optionally a port number. For example: `ldaps://ldap.example.com:636` |
| `--base-dn` | `BATON_BASE_DN`   |  **optional** Base Distinguished name to search for LDAP objects in, for example `DC=example,DC=com` |
| `--user-search-dn` | `BATON_USER_SEARCH_DN` |  **optional**  Distinguished name to search for User objects in.  If unset the Base DN is used. |
| `--group-search-dn` | `BATON_GROUP_SEARCH_DN` |  **optional**  Distinguished name to search for Group objects in.  If unset the Base DN is used. |
| `--role-search-dn` | `BATON_ROLE_SEARCH_DN` |  **optional**  Distinguished name to search for Role objects in.  If unset the Base DN is used. For example: `cn=roles,cn=accounts,dc=example,dc=com`. Role entries must also have a `cn=roles` component in their own DN — pointing this at a container without one syncs zero roles. |
| `--filter` | `BATON_FILTER` |  **optional**  An additional LDAP filter applied to every search. For example `(!(objectClass=computer))` excludes every entry with that object class. |
| `--insecure-skip-verify` | `BATON_INSECURE_SKIP_VERIFY` |  **optional**  When connecting over TLS, skip verification of the server certificate. `true` or `false`.  Defaults to `false` |
| `--disable-operational-attrs` | `BATON_DISABLE_OPERATIONAL_ATTRS` |  **optional**  Do not fetch operational attributes. Some LDAP servers do not support them. When set, `created_at` and last login are not synced. `true` or `false`.  Defaults to `false` |
| `--provisioning` | `BATON_PROVISIONING` |  **optional** Enable provisioning by `baton-ipa`: grant and revoke on group `member` and `manager` and on role `member`. `baton-ipa` also declares user account deletion as a capability, but that path currently errors instead of deleting: the resource ID the connector stores for a user (`ipaUniqueID`) doesn't match what the delete path expects (a DN). `true` or `false`.  Defaults to `false` |

Use `baton-ipa --help` to see all configuration flags and environment variables.

# Developing baton-ipa

## How to test on an ARM-based Mac using podman

### Install and configure podman
```
brew install podman
podman machine init
podman machine start
```

### Allow binding to port < 1024 on the podman VM
> **Warning**: Proceed with caution. By default, rootless users are not allowed to bind to ports under 1024. FreeIPA requires ports 80 and 443 for access to the admin UI. If you are only accessing via LDAP, skip this step.

```
podman machine ssh

sudo vi /etc/sysctl.conf

### Add the following entry to /etc/sysctl.conf:
net.ipv4.ip_unprivileged_port_start=80

### Save and exit session

podman machine stop
podman machine start
```

### Install and configure FreeIPA
```
podman pull quay.io/freeipa/freeipa-server:almalinux-10

podman volume create freeipa-data
    
podman run --name freeipa -ti -h ipa.example.test --read-only \
    -v freeipa-data:/data:Z \
    -e PASSWORD=Secret123 \
    -p 80:80 -p 22389:389 -p 22636:636 -p 443:443 \
    freeipa-server:almalinux-10 ipa-server-install -r EXAMPLE.TEST --no-ntp --no-ui-redirect

# You will be prompted with a series of configuration questions. Fill them out to complete the configuration.
```

## Configure access to the Admin UI

The FreeIPA container requires access via a domain name. 

Configure a hosts entry on your local machine to point example.test to 127.0.0.1.

Edit `/etc/hosts` and add an entry:
```
ipa.example.test 127.0.0.1
```

The Admin UI should accessible by browsing to `https://ipa.example.test`.

Username: `admin`
Password: `Secret123`

## Testing
FreeIPA should now be running. Create new resources on the FreeIPA server. Use the `baton-ipa` cli to sync the data from the FreeIPA server with the example command below.
```
baton-ipa --url ldap://localhost:22389 --bind-dn uid=admin,cn=users,cn=accounts,dc=example,dc=test --password Secret123
```

After successfully syncing data, use the baton CLI to list the resources and see the synced data.
`baton resources`
`baton stats`

# Data Model

`baton-ipa` syncs the following IPA resource types:

- Users (`posixAccount`)
- Groups (`ipaUserGroup`) — entitlements: `member`, `manager`
- Roles (`groupOfNames` under the role search DN, matching entries also need a `cn=roles` component in their own DN) — entitlement: `member`, grantable to users, groups, hosts and host groups
- Hosts (`ipaHost`)
- Host groups (`ipaHostGroup`) — entitlements: `member`, `manager`, plus HBAC-derived rules

HBAC rules (`ipaHBACRule`) are read but are not synced as a resource type of their own. They are the source of the entitlements that appear on hosts and host groups: each rule naming a host or host group becomes an entitlement on it. A rule whose `hostCategory` or `userCategory` is `all` — including the `allow_all` rule FreeIPA ships — is emitted against a single virtual `any-host` or `anyone-group` resource (displayed in C1 as **Any** or **Anyone**) rather than expanded across every host.

`baton-ipa` will sync information only from under the base DN specified by the `--base-dn` flag in the configuration.

# Contributing, Support and Issues

We started Baton because we were tired of taking screenshots and manually building spreadsheets. We welcome contributions, and ideas, no matter how small -- our goal is to make identity and permissions sprawl less painful for everyone. If you have questions, problems, or ideas: Please open a Github Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.
