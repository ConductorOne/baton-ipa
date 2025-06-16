![Baton Logo](./docs/images/baton-logo.png)

# `baton-ipa` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-ipa.svg)](https://pkg.go.dev/github.com/conductorone/baton-ipa) ![main ci](https://github.com/conductorone/baton-ipa/actions/workflows/main.yaml/badge.svg)

`baton-ipa` is a connector for IPA (Identity, Policy & Audit) Servers built using the [Baton SDK](https://github.com/conductorone/baton-sdk). It communicates using the LDAP protocol to sync data about roles, users, and groups.

Check out [Baton](https://github.com/conductorone/baton) to learn more about the project in general.

## LDAP

## Credentials

To access the IPA server, you must provide the username and password you use to login to the IPA server. 

# Getting Started

_Also see [Set up an LDAP connector](https://www.conductorone.com/docs/product/integrations/ldap/) in the ConductorOne documentation for instructions including using LDAP from ConductorOne._

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
| `--group-search-dn` | `BATON_GROUP_SEARCH_DN` |  **optional**  Distinguished name to search for User objects in.  If unset the Base DN is used. |
| `--provisioning` | `BATON_PROVISIONING` |  **optional** Enable Provisioning of Groups and Roles by `baton-ipa`. `true` or `false`.  Defaults to `false` |

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
Once the FreeIPA container is running, you should be able to initiate a sync using:

```
baton-ipa --url ldap://localhost:22389 --bind-dn uid=admin,cn=users,cn=accounts,dc=example,dc=test --password Secret123
```

After creating new resources on the LDAP server, use the `baton-ipa` cli to sync the data from the LDAP server with the example command below.
`baton-ipa --base-dn dc=example,dc=org --bind-dn cn=admin,dc=example,dc=org --password admin --domain localhost`

After successfully syncing data, use the baton CLI to list the resources and see the synced data.
`baton resources`
`baton stats`

# Data Model

`baton-ipa` will fetch information about the following IPA resources:

- Users
- Roles
- Groups
- Host
- Host Groups
- HBAC Rules

`baton-ipa` will sync information only from under the base DN specified by the `--base-dn` flag in the configuration.

# Contributing, Support and Issues

We started Baton because we were tired of taking screenshots and manually building spreadsheets. We welcome contributions, and ideas, no matter how small -- our goal is to make identity and permissions sprawl less painful for everyone. If you have questions, problems, or ideas: Please open a Github Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.
