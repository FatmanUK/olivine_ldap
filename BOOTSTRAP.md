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

- **Documentation and plan only.** Three tracked files — `.gitmodules`,
  `CLAUDE.md`, `BOOTSTRAP.md` — plus the `openldap/` submodule at
  `OPENLDAP_REL_ENG_2_7_1`. There is no Go in the repository yet: no
  `go.mod`, no `internal/`, no `Makefile`.
- Host toolchain: Go 1.26.5, Podman 5.8.3.
- The module path is settled by the remote:
  `github.com/FatmanUK/openldap_olivine`. Note that the remote repository
  name inverts the local directory name (`olivine_ldap`); the Go module path
  follows the remote.

## 2. Next Three Steps

The plan is `~/.claude/plans/a-green-stone-in-the-socket.md`, and it is
authoritative for sequencing. In brief:

1. ~~Reconcile the documentation with reality.~~ Done — this commit.
2. **Repository skeleton.** `go.mod` on `github.com/FatmanUK/openldap_olivine`,
   a `Makefile` whose targets are the contract (`build`, `test`,
   `golden-build`, `golden`, `lint`), and the package layout.
3. **The BER codec, `internal/ber`**, ported from
   `libraries/liblber/{decode,encode,io}.c`. Everything sits on it, so it goes
   first.

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
layout. None of these exist yet.

| Go package | Ported from |
|---|---|
| `internal/ber` | `libraries/liblber/{decode,encode,io}.c` |
| `internal/ldap` | protocol messages, RFC 4511 |
| `internal/server` | `servers/slapd/{daemon,connection}.c` |
| `internal/schema` | `servers/slapd/{at,oc,syntax,mr,schema_init}.c` |
| `internal/dn` | `servers/slapd/dn.c` |
| `internal/store` | new — Postgres/GORM, no C analogue |
| `internal/golden` | new — the oracle |

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
- **New code says TLS, not SSL** — it's been TLS for over 20 years. Time to
  drop the SSL nomenclature (except where it would cause a problem).

### 3.4 Other

- **Go source is 70 columns, tab counted as 8.**
- **Store tests must never share a database with a real world.** The scratch
  schema goes in the connection string, not a `SET search_path`: GORM pools
  connections, so the SET reaches one of them and every other query lands in
  `public`.
- **GPG signing times out regularly** (a gnome3 pinentry issue, not a code
  problem). The fix is always to retry the identical `git commit` once the
  user has unlocked the key. Never use `--no-gpg-sign`.

## 4. Dependency Map

**External Go modules** — *intended, not present.* There is no `go.mod`
yet; this is the dependency set the skeleton will declare:

- `golang.org/x/crypto` — Argon2id
- `gorm.io/gorm` + `gorm.io/driver/postgres` (+ transitive `jackc/pgx`,
  `pgpassfile`, `pgservicefile`, `puddle`) — persistence

**External non-Go dependency**:

Podman (rootless), for the deployment containers and for the golden oracle
built from `openldap/`.

`openldap/` is a leaf that only the generator scripts and `make golden-build`
read. No Go package imports it.

## 5. Version Log

Most recent first.

| Commit | Summary |
|---|---|
| `cceb99c` | Add CLAUDE.md and BOOTSTRAP.md |
| `1577993` | Add openldap submodule |
| `32aa4b7` | Commit nothing |

Working branch: `mother`. Never merge the `openldap/`-adjacent branches
into `mother`; they are read-only reference.

## 6. Testing Status

Nothing tested yet, because there is nothing to test. The first tests arrive
with `internal/ber` (plan step 3): table-driven round-trips plus a fuzz target
on the decoder. A malformed-length panic in the decoder is a remote crash
later, and under crash-only architecture a panic is a restart.

The golden harness (plan step 5) is deliberately sequenced before schema and
the operations, so that everything from that point on is verified against the
C rather than reasoned about.
