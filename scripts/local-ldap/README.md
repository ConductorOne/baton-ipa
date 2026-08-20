# Local LDAP harness

An OpenLDAP server seeded with an IPA-shaped directory, for running the
connector end-to-end on a machine that cannot run the FreeIPA container image
(it needs systemd and privileged cgroup access).

`.github/workflows/ci.yaml` runs against a real FreeIPA server and remains the
authoritative integration test. `ipa.schema` here is a **minimal approximation**
of the IPA schema — just the attributes and object classes the connector's
filters touch (`ipaUniqueID`, `ipausergroup`, `ipahost`, `ipahostgroup`,
`ipahbacrule`, `memberManager`, `memberHost`, `memberUser`, `hostCategory`,
`userCategory`) — on a private OID arc. Object class names are lowercase
because that is how FreeIPA stores them, and `objectClassesToResourceTypes` is
keyed on lowercase names. `ipausergroup`/`ipahostgroup` are structural with an
optional `member` rather than auxiliary over `groupOfNames`, because IPA groups
may have no members and `groupOfNames` would make revoking the last one a schema
violation. Roles stay `groupOfNames`, which is what IPA uses and what
`roleFilter` matches.

## Use

```bash
apt-get install -y slapd ldap-utils   # once

scripts/local-ldap/start.sh           # starts slapd on 127.0.0.1:3389
eval "$(scripts/local-ldap/env.sh)"
go build ./cmd/baton-ipa

./baton-ipa --file=sync.c1z
baton resources --file=sync.c1z
baton grants --file=sync.c1z

scripts/local-ldap/check.sh           # assert the DN-dependent grants (needs the baton CLI)
scripts/local-ldap/start.sh --stop
```

Note that a released `baton` CLI built against an older baton-sdk **silently
drops** fields the newer `Resource` proto added - including the top-level
`profile`, which is where this connector keeps the DN. `baton grants` and `baton
entitlements` are still trustworthy, but `baton resources` can show
`profile: null` for a resource that definitely has one. To inspect profiles, dump
the c1z with a small program built against this module's own vendored SDK
(`dotc1z.NewC1ZFile` + `ListResources`) rather than trusting the CLI's output.

`scripts/grant-revoke.sh` also works against it:

```bash
BATON_LDAP=./baton-ipa BATON=baton \
  BATON_ENTITLEMENT="group:33333333-3333-3333-3333-333333333333:member" \
  BATON_PRINCIPAL="22222222-2222-2222-2222-222222222222" \
  BATON_PRINCIPAL_TYPE=user \
  scripts/grant-revoke.sh
```

Pick a grant/revoke principal that no *other* membership reaches: testgroup1 is a
member of testrole1, so a role grant/revoke for testuser1 (a member of
testgroup1) never looks revoked - grant expansion re-derives it. testuser2 only
manages the group, so it is the safe principal. `grant-revoke.sh` also leaves the
grant in place when it finishes, so re-run `start.sh` between runs.

Re-run `start.sh` to reset the directory to the fixtures — it rebuilds the
database from scratch.

## Fixtures

`fixtures.ldif` mirrors the IPA DIT under `dc=example,dc=test` with fixed
`ipaUniqueID`s so assertions can be written without looking IDs up:

| object | id | notes |
|---|---|---|
| `uid=testuser1` | `1111…` | member of testgroup1, testrole1, testhbac1 |
| `uid=testuser2` | `2222…` | manager of testgroup1 and testhostgroup1 |
| `cn=testgroup1` | `3333…` | member of testrole1 |
| `fqdn=host1.example.test` | `4444…` | member of testhostgroup1 |
| `cn=testhostgroup1` | `5555…` | attached to testhbac1 |
| `cn=testhbac1` | `6666…` | allows testuser1 on testhostgroup1 |
| `cn=allow_all` | `7777…` | `hostCategory`/`userCategory` = all |
| `cn=testrole1` | (entryUUID) | roles have no ipaUniqueID |

## Testing hosted-mode behavior

c1 does not persist `Resource.ExternalId`, so in hosted mode the resource passed
to `Entitlements()`/`Grants()` never carries it — while a CLI sync round-trips
the resource through the c1z, where it survives. That divergence is why CXP-594
and CXP-842 both shipped: the failing path was unreachable locally.

`getDNFromResource()` now prefers the trait profile `path` (the carrier c1 does
persist), so a normal CLI run takes the same branch hosted mode takes. To
emulate hosted mode exactly, delete the `rs.WithExternalID(...)` options from the
resource builders in `pkg/connector` and re-run the steps above: the sync must
still succeed and `check.sh` must still pass.
