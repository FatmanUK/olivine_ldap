# Olivine LDAP

[![Test](https://github.com/FatmanUK/olivine_ldap/actions/workflows/test.yml/badge.svg)](https://github.com/FatmanUK/olivine_ldap/actions/workflows/test.yml)
[![Build](https://github.com/FatmanUK/olivine_ldap/actions/workflows/build.yml/badge.svg)](https://github.com/FatmanUK/olivine_ldap/actions/workflows/build.yml)
[![Push](https://github.com/FatmanUK/olivine_ldap/actions/workflows/push.yml/badge.svg)](https://github.com/FatmanUK/olivine_ldap/actions/workflows/push.yml)

A from-scratch **Go** reimplementation of **OpenLDAP**, behaviour-
compatible with the original — while deliberately replacing six things
that have aged worst in the C:

| OpenLDAP (C) | Olivine LDAP (Go) |
|---|---|
| Manual memory management | Go, memory-safe |
| Unencrypted connections | **TLS only** |
| Flat-file database | **Postgres** with GORM |
| autotools | Rootless **Podman** container |
| complex save and restore routines | crash-only architecture |
| high-availability very hard or impossible | high-availability almost effortless |

Behaviour compatibility is not a claim, it is a test. OpenLDAP is
vendored as a submodule, built into a container, and driven with the same
bytes as Olivine; the transcripts are diffed. Where upstream's behaviour
differs from what its source reads like, the comment says so and cites
the file and line.

## What works

Olivine answers LDAPv3 over TLS, and upstream's own clients talk to it.

- **Operations**: bind (simple and SASL), search, add, modify, delete,
  compare, modrdn, abandon, unbind, and the whoami extended operation
  (RFC 4532). Operations run concurrently per connection, so abandon
  abandons something.
- **Schema**: RFC 4512 definitions, the equality, ordering and substring
  matching rules, syntax validation, and schema checking with slapd's own
  result codes. The standard schema is embedded, derived from slapd's own
  `cn=Subschema` rather than transcribed, so a Go-only checkout needs no
  files to find.
- **Access control** in slapd's `access to … by …` syntax, with its
  levels — `none` through `manage` — and per-attribute selection.
- **Search limits** and **paged results** (RFC 2696).
- **SASL** over TLS: EXTERNAL binds as the client certificate, PLAIN
  carries a DN and password, and GSSAPI is Kerberos 5 through `gokrb5`.
- **`cn=config`** is readable *and* writable, backed by Postgres, so a
  configuration change applies to every replica without a redeploy.

Not implemented, each for a reason recorded in `BOOTSTRAP.md` §3.3:
syncrepl (Postgres replicates instead), StartTLS (there is no cleartext
listener to upgrade), proxy authorization, GSS-SPNEGO, and the ACL
features that would need `authz-regexp` or regular-expression DN
matching. The `slap*` tools are out of scope: they link slapd's backend
directly rather than opening a socket, so no amount of protocol work
would make them read a Postgres database.

## Running it

TLS is mandatory. A missing certificate is a configuration error, not a
reason to fall back.

```bash
make build                     # bin/olivined
./bin/olivined -hash secret    # a password hash for the root DN
```

Configuration comes from the environment — `./bin/olivined` with no
certificate prints the whole list. The essentials:

```bash
OLIVINE_TLS_CERT=/path/cert.pem \
OLIVINE_TLS_KEY=/path/key.pem \
OLIVINE_DSN='host=db user=olivine dbname=olivine sslmode=require' \
OLIVINE_SUFFIX='dc=example,dc=com' \
OLIVINE_ROOT_DN='cn=admin,dc=example,dc=com' \
OLIVINE_ROOT_PASSWORD_HASH='{ARGON2}...' \
./bin/olivined
```

The suffixes, the access policy, the root identity and the search limits
are **defaults for first boot**. They are stored in the database on the
first start and read back from it afterwards, so they can be changed over
LDAP by modifying `cn=config` — and the change reaches every replica.
What is needed before the database can be reached, and so has nowhere
else to come from, is read from the environment every time: the DSN, the
TLS material, the listen address, the Kerberos keytab.

### In a container

```bash
make pod-build   # a ~19 MB image from scratch: one static binary
make pod-run     # smoke-test it against a throwaway Postgres
```

The image has no shell and no package manager, runs as uid 10001 and
listens on 6360. `make pod-run` is the end-to-end check: it stands the
image up and drives it with upstream's own `ldapsearch`, `ldapmodify`
and `ldapwhoami`.

## The golden-output harness

This is the part worth knowing about. `internal/golden` builds a test
database, drives the same script through OpenLDAP — built from the
pinned submodule, in a rootless container — and through Olivine in
process, then diffs the transcripts.

```bash
make golden-build    # build the C oracle from openldap/
make golden          # protocol
make golden-data     # searches over a seeded tree on both sides
make golden-acl      # nine access policies
make golden-limits   # size and time limits
make golden-paged    # paged results, four page sizes
make golden-sasl     # a SASL EXTERNAL bind
make golden-gssapi   # a SASL GSSAPI bind, against a real KDC
```

It was built early, before the schema and the operations, so that
everything after it is verified rather than reasoned about — and it has
corrected this implementation about a dozen times. A few of the
corrections:

- a `>=` filter on an attribute with no ORDERING rule matches **nothing**
  (`filterentry.c:648-658`), rather than falling back to some other
  comparison;
- `+` returns operational attributes *only*, not everything;
- back-mdb renames whole subtrees, so modrdn does not refuse a non-leaf;
- StartTLS when TLS is already up is `operationsError`, not
  `unwillingToPerform`;
- a malformed `olcAccess` value answers `other`, because `aclparse.c`
  never sets `reply.err` and the failure falls through at
  `bconfig.c:6034`.

Where the protocol leaves something open — which entries a truncated
search returns, how a paged cookie is spelled, how many rounds a SASL
mechanism takes — the harness compares only what is promised, and the
code says why.

`golden-gssapi` is shaped differently on purpose: the client is
upstream's own `ldapwhoami`, driven at each server in turn, because a
GSSAPI *initiator* written in Go would be a second implementation of the
thing under test.

## Developing

```bash
make test        # unit tests; hermetic, no container needed
make store       # the store tests, against a throwaway Postgres
make race        # the same under the race detector
make lint        # gofmt, go vet, and the style invariants
make help        # every target
```

Go source is 70 columns wide, counting a tab as 8, and functions are 40
lines at most. `scripts/check-style.sh` enforces both, over tracked *and*
untracked files — an earlier version read only the index, and new code
passed right up until someone staged it.

The C reference is a submodule at `openldap/`, pinned to a release tag
and never edited:

```bash
git submodule update --init openldap
git -C openldap/ describe --tags --always
```

It is not needed to build, test or run — the standard schema is embedded,
which is what lets the CI check out without submodules and still run the
whole default suite. Only the golden harness reads it.

**Check the C before implementing anything that claims to match
upstream.** Several behaviours here look like bugs until you read the
original, and several plausible-looking assumptions turned out to be
wrong when checked.

## Documentation

- `CLAUDE.md` — how to work in this repository.
- `BOOTSTRAP.md` — what has landed (§2), the upstream behaviours that are
  easy to get wrong (§3.1), the architecture (§3.2), and every deliberate
  departure with its reason (§3.3). Read §3.3 before changing anything
  that looks odd.
- `internal/*/README.md` — the per-package notes, where there is
  something to say that the code cannot.
