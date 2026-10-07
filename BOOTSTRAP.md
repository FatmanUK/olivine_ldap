# BOOTSTRAP.md — Olivine LDAP

Written so a fresh agent — or a competing LLM — can resume this project after
total loss of session state. If this file and the repo disagree, **the repo
wins**: this is a snapshot, not a source of truth.

Read `CLAUDE.md` first. It is the working contract and is loaded into every
session; this file is the orientation around it.

## 1. Current Goal

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

### Where it stands

- **Skeleton standing, no protocol code.** `go.mod`, a `Makefile` whose
  targets are the contract, the package layout under `internal/`, and
  `cmd/olivined`. Every package is a `doc.go` stating what it is ported
  from; none has an implementation.
- `make lint`, `make test` and `make build` all pass. The binary builds and
  answers `-version`; invoked as a server it reports that it is not
  implemented and exits 1.
- `make golden` and `make golden-build` exist and fail deliberately,
  pointing at plan step 5.
- Host toolchain: Go 1.26.5, Podman 5.8.3.
- The module path is settled by the remote:
  `github.com/FatmanUK/openldap_olivine`. Note that the remote repository
  name inverts the local directory name (`olivine_ldap`); the Go module path
  follows the remote.

## 2. Next Three Steps

The plan is `~/.claude/plans/a-green-stone-in-the-socket.md`, and it is
authoritative for sequencing. In brief:

1. ~~Reconcile the documentation with reality.~~ Done, `db5fd8e`.
2. ~~Repository skeleton.~~ Done — this commit.
3. **The BER codec, `internal/ber`**, ported from
   `libraries/liblber/{decode,encode,io}.c`. Everything sits on it, so it
   goes first. Table-driven round-trips plus a fuzz target on the decoder:
   a malformed-length panic there is a remote crash later, and under
   crash-only architecture a panic is a restart.
4. **TLS listener and connection lifecycle**, matching the dispatch at
   `connection.c:1080-1089`.

The plan carries the ordering beyond that, and three open questions —
whether `syncrepl.c` is ported at all, whether `cn=config` becomes a
read-only projection of the environment, and how far SASL goes beyond simple
bind over TLS — each tagged with the step it blocks.

## 3. Project State

### 3.1 Key Logic

No code yet. Two decisions already taken about the BER layer, because they
determine its shape:

- **The resumable reader is not ported.**
  `libraries/liblber/io.c:473` carries a comment explaining that
  `ber_get_next` "can safely be called multiple times for the same packet"
  and resumes where it stopped. That state machine exists because slapd
  multiplexes connections over a poll loop. A goroutine per connection blocks
  on `io.ReadFull` instead, and the resumption state is dead weight. This is
  the first place the Go will look wrong to someone reading the C.
- **`ber_printf`/`ber_scanf` are not reimplemented.** The variadic format
  language is replaced by typed encode/decode against the message structs.
  Confirm against `encode.c` that no on-the-wire behaviour hides in the
  format layer before discarding it.

### 3.2 Architecture

Package layout, mirroring the C's separation of concerns rather than its file
layout. All of these exist as `doc.go` only; the implementations do not.

| Go package | Ported from |
|---|---|
| `internal/ber` | `libraries/liblber/{decode,encode,io}.c` |
| `internal/ldap` | protocol messages, RFC 4511 |
| `internal/server` | `servers/slapd/{daemon,connection}.c` |
| `internal/schema` | `servers/slapd/{at,oc,syntax,mr,schema_init}.c` |
| `internal/dn` | `servers/slapd/dn.c` |
| `internal/store` | new — Postgres/GORM, no C analogue |
| `internal/golden` | new — the oracle |
| `cmd/olivined` | `servers/slapd` (the daemon entry point) |

The operation dispatch to match is `servers/slapd/connection.c:1080-1089`.

TLS-only means `servers/slapd/starttls.c` is deliberately not ported, but the
StartTLS extended operation must still be *recognised* and answered
`unwillingToPerform` — not met with silence or a parse error.

### 3.3 Decisions

Departures from the plan or from naive C-to-Go translation, recorded so they
are not "fixed" back by accident.

**Structural:**

- **The C reference is a submodule** at `openldap/`, pinned to tag OPENLDAP_REL_ENG_2_7_1
  rather than a moving branch. This is the upstream C reference.

**Compatibility choices:**

- **TLS only** — no cleartext, no STARTTLS.
- **Argon2id passwords** by default, with legacy algorithms read but not
  written. This is a divergence in *default*, not in format: upstream already
  ships argon2 as an optional loadable module at
  `servers/slapd/pwmods/argon2.c`, scheme tag `{ARGON2}`, argon2id with
  iterations 5, memory 7168 KiB, parallelism 1, 16-byte salt and 32-byte
  hash. Matching those parameters keeps hashes mutually readable between the
  two implementations, so match them unless there is a reason not to — and
  record the reason.
- **The daemon is `olivined`, not `slapd`.** The name follows the C's
  daemon convention (`slapd`, `lloadd`) rather than reusing `slapd`, because
  the two are not drop-in substitutes: Olivine is TLS-only and configured
  from the environment, so anything invoking `slapd` with a `slapd.conf`
  would fail in confusing ways. Better to fail at "command not found".
- **New code says TLS, not SSL** — it's been TLS for over 20 years. Time to
  drop the SSL nomenclature (except where it would cause a problem).

### 3.4 Other

- **Go source is 70 columns, tab counted as 8**, and functions are 40 lines
  at most. Both are enforced by `scripts/check-style.sh`, which `make lint`
  runs via `make style`. It reads `git ls-files --cached --others
  --exclude-standard`, so files that are written but not yet staged are
  checked too — an earlier version read only the index, and new code passed
  the check right up until someone staged it.
- **Store tests must never share a database with a real world.** The scratch
  schema goes in the connection string, not a `SET search_path`: GORM pools
  connections, so the SET reaches one of them and every other query lands in
  `public`.
- **GPG signing times out regularly** (a gnome3 pinentry issue, not a code
  problem). The fix is always to retry the identical `git commit` once the
  user has unlocked the key. Never use `--no-gpg-sign`.

## 4. Dependency Map

**External Go modules** — `go.mod` exists and declares *no* dependencies.
Nothing is required until the code that needs it lands, and a module listed
early is one `go mod tidy` removes again. This is the set expected to arrive,
with the step that brings it:

- `golang.org/x/crypto` — Argon2id (step 8, bind)
- `gorm.io/gorm` + `gorm.io/driver/postgres` (+ transitive `jackc/pgx`,
  `pgpassfile`, `pgservicefile`, `puddle`) — persistence (step 7)

The BER codec, the protocol layer and the TLS listener need nothing outside
the standard library.

**External non-Go dependency**:

Podman (rootless), for the deployment containers and for the golden oracle
built from `openldap/`.

`openldap/` is a leaf that only the generator scripts and `make golden-build`
read. No Go package imports it.

## 5. Version Log

Most recent first.

A commit cannot record its own hash, so this log necessarily lags by one.
The newest entry is the commit before HEAD.

| Commit | Summary |
|---|---|
| `db5fd8e` | Reconcile the docs with the actual repository state |
| `cceb99c` | Add CLAUDE.md and BOOTSTRAP.md |
| `1577993` | Add openldap submodule |
| `32aa4b7` | Commit nothing |

Working branch: `mother`. Never merge the `openldap/`-adjacent branches
into `mother`; they are read-only reference.

## 6. Testing Status

No Go tests yet — `make test` reports "no test files" for all eight
packages, which is the honest result and not a passing suite. What *is*
verified is the toolchain: `make lint`, `make test` and `make build` pass,
and `scripts/check-style.sh` was checked against a deliberately bad file to
confirm it fails on both an 87-column line and a 42-line function. A style
checker that cannot fail is worse than none.

The first real tests arrive with `internal/ber` (plan step 3): table-driven
round-trips plus a fuzz target on the decoder. A malformed-length panic in
the decoder is a remote crash later, and under crash-only architecture a
panic is a restart.

The golden harness (plan step 5) is deliberately sequenced before schema and
the operations, so that everything from that point on is verified against the
C rather than reasoned about.
