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

## Quickstart: a local test server

Everything you need for a server you can actually bind to, with nothing
left as a placeholder.

```bash
make build
```

**A certificate.** TLS is mandatory — there is no cleartext fallback — so
a self-signed pair is the minimum to start. This is the same shape
`scripts/pod-run.sh` generates for its own smoke test:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	-keyout key.pem -out cert.pem -days 365 \
	-subj "/CN=localhost" -addext "subjectAltName=DNS:localhost"
```

**A root password hash.** `-hash` prints one and exits; nothing is
written anywhere, so pipe it straight into the variable it's for:

```bash
hash=$(./bin/olivined -hash supersecret)
```

**A database.** `scripts/postgres-up.sh` starts a throwaway, rootless
Postgres container and prints its connection string on stdout — this is
also where a connection password goes, as `password=` in that string:

```bash
dsn=$(./scripts/postgres-up.sh)
```

**The server itself.** `OLIVINE_LISTEN` has to be set: the default is
`:636`, the standard ldaps port, and an unprivileged process cannot bind
anything below 1024 — the same reason the container sets it to `:6360`
(see `deploy/Containerfile`). Any high port will do locally:

```bash
OLIVINE_LISTEN=:1636 \
OLIVINE_TLS_CERT=cert.pem \
OLIVINE_TLS_KEY=key.pem \
OLIVINE_DSN="$dsn" \
OLIVINE_SUFFIX='dc=example,dc=com' \
OLIVINE_ROOT_DN='cn=admin,dc=example,dc=com' \
OLIVINE_ROOT_PASSWORD_HASH="$hash" \
./bin/olivined
```

**Confirm it, from another shell**, with any LDAPv3 client — here,
OpenLDAP's own:

```bash
LDAPTLS_REQCERT=never ldapsearch -H ldaps://localhost:1636 \
	-x -b '' -s base -LLL namingContexts

LDAPTLS_REQCERT=never ldapwhoami -H ldaps://localhost:1636 \
	-x -D 'cn=admin,dc=example,dc=com' -w supersecret
```

**Tear down** when done — `postgres-up.sh`'s container is not removed
automatically, so that `make store` can reuse it between runs:

```bash
make postgres-down
```

The suffix, the access policy, the root identity and the search limits
set above are **defaults for first boot only**. They are stored in the
database on the first start and read back from it afterwards, so a
second run of the same command with a different `OLIVINE_SUFFIX` does
nothing — the stored value already won. Changing any of them afterwards
means modifying `cn=config` over LDAP, not re-exporting the variable.
What *is* read from the environment every time is whatever is needed
before the database can be reached at all: the DSN, the TLS material,
the listen address, the Kerberos keytab.

Skipping `OLIVINE_DSN` entirely is a legitimate smaller step: the server
still starts and answers TLS, and every operation answers
`unwillingToPerform` — enough to confirm the listener and the
certificate before wiring up Postgres at all.

### In a container

```bash
make pod-build   # a ~19 MB image from scratch: one static binary
make pod-run     # smoke-test it against a throwaway Postgres
```

`pod-run` is not just a build check. It stands up a dedicated bridge
network, a throwaway Postgres on it, and the server image — generating
its own CA, server certificate and client certificate as it goes — then
drives the running container with upstream's own `ldapsearch`,
`ldapmodify` and `ldapwhoami`, including a SASL EXTERNAL bind by client
certificate and a live `cn=config` write. Everything it creates is
removed on exit, success or failure, and it never touches `make store`'s
Postgres or another project's containers.

The image has no shell and no package manager, runs as uid 10001 and
listens on 6360 — map it with `podman run -p 636:6360 …` to serve the
standard port from outside.

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
make golden-gssapi   # a SASL GSSAPI bind, two realms, a real KDC
```

`golden-build` (`scripts/golden-build.sh`) is the one to run first, and
the one whose caching is worth understanding: it tags the oracle image
with the submodule's own commit (`git -C openldap describe --tags`), so
a stale image is never silently reused across a submodule bump, and a
current one is never needlessly rebuilt. `FORCE=1 make golden-build`
rebuilds anyway.

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
  `bconfig.c:6034`;
- a cross-realm GSSAPI identity keeps its realm *inside* the `uid` value —
  `uid=tester@other.test` — where `slap_sasl_getdn` reads as though it
  would get a `cn=OTHER.TEST` RDN of its own. Reading the C told the truth
  about slapd and not about Cyrus.

Where the protocol leaves something open — which entries a truncated
search returns, how a paged cookie is spelled, how many rounds a SASL
mechanism takes — the harness compares only what is promised, and the
code says why.

`golden-gssapi` is shaped differently on purpose: the client is
upstream's own `ldapwhoami`, driven at each server in turn, because a
GSSAPI *initiator* written in Go would be a second implementation of the
thing under test.

## Scripts

Everything under `scripts/` is invoked through a `make` target — nothing
here needs running by hand — but knowing what each one actually does
makes the targets less opaque.

| Script | What it does |
|---|---|
| `postgres-up.sh` / `postgres-down.sh` | Start and remove the throwaway Postgres behind `make store` and the quickstart above. `up` prints the connection string on stdout, bound to `127.0.0.1:15432` so it can never be mistaken for a real instance; `down` removes only the container this project named. |
| `pod-run.sh` | The container smoke test — see "In a container" above. |
| `golden-build.sh` | Builds the C oracle from the `openldap/` submodule, tagged by its commit. See "The golden-output harness" above. |
| `check-style.sh` | Enforces the 70-column, 40-line-function rule, over tracked *and* untracked files — `git ls-files --cached --others --exclude-standard`. Run by `make lint` / `make width-check`. |
| `capture-subschema.sh`, `capture-dn.sh` | Capture slapd's own output — `cn=Subschema`, and `slapdn`'s normalisation — into testdata, so the schema parser and `internal/dn` are checked against what slapd actually emits rather than a transcription of the RFC. Needs the oracle image (`make golden-build` first). |
| `derive-builtin.sh`, `derive-standard.sh` | Derive the schema Olivine embeds — the attributes `schema_init.c` hardcodes, and the standard set slapd loads — from the captured subschema, so neither can drift from the upstream it came from. |
| `gssapi-*.sh` | Stand up a two-realm Kerberos KDC inside the oracle container for `make golden-gssapi`; see `internal/gss/README.md` for why two realms. |

The capture/derive scripts are a maintainer workflow, not a day-to-day
one: run them in that order (`golden-build` → `capture-*` → `derive-*`)
only after bumping the `openldap/` submodule to a new release, to bring
the embedded schema up to date with it.

## Developing

```bash
make test        # unit tests; hermetic, no container needed
make store       # the store tests, against a throwaway Postgres
make race        # the same under the race detector
make lint        # gofmt, go vet, and the style invariants
make help        # every target
```

Go source is 70 columns wide, counting a tab as 8, and functions are 40
lines at most — see `check-style.sh` above.

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

## License

GPLv3 or later. See `LICENSE` for the full text.

Chosen deliberately, and differently from OpenLDAP itself, which
uses its own permissive license: GPL was picked so that anyone who
distributes a modified Olivine has to release the source for their
changes. `gokrb5` (Apache-2.0) is the only dependency that matters
here, because Apache-2.0 and GPLv2 are mutually incompatible — the
reason this is GPLv3 and not GPLv2.

```
Olivine LDAP
Copyright (C) 2026  Adam J. Richardson

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```
