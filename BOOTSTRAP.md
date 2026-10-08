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

- **It serves.** `olivined` listens on TLS, reads LDAPMessages, dispatches
  them, and answers with well-formed LDAPResults. Verified against the real
  binary: TLS 1.3 handshake succeeds, and a cleartext LDAP client gets
  nothing back.
- **`internal/ber`** — decoder, encoder, framing reader. 64 tests, 83.9%
  coverage, three fuzz targets run for ~17M executions, cross-checked against
  `encoding/asn1` where BER and DER agree.
- **`internal/ldap`** — envelope, operation and response tags, result codes,
  controls, response encoder. 82.9% coverage, fuzzed for ~10M executions.
- **`internal/server`** — TLS-only listener, goroutine per connection,
  dispatch. 80.5% coverage, race-clean.
- **Bind, search, add, modify, delete and compare work**, and `make
  golden-data` shows Olivine matching real slapd byte-for-byte on all four
  search scopes, equality filters, case-insensitive matching, a missing base,
  and compare — identical requests against identically seeded trees.
- Passwords are Argon2id with upstream's exact parameters; `{SSHA}`, `{SHA}`
  and unprefixed values are read but never written.
- **Schema checking matches slapd's codes exactly**, including the surprising
  one: an undefined objectClass is `invalidSyntax` (21), not
  `objectClassViolation` (65). Every code and diagnostic was captured from the
  oracle, not guessed.
- Not implemented: modrdn, the root DSE, abandon's actual effect, SASL,
  paged results, and the matching-rule semantics from step 6's second half.
- StartTLS is refused with `operationsError`, critical unknown controls draw
  `unavailableCriticalExtension`, and malformed input draws a notice of
  disconnection.
- **`internal/golden` is the oracle, and it runs.** `make golden-build`
  compiles OpenLDAP 2.7.1 from the submodule into a rootless Podman image
  (~5 minutes, ~97 MB); `make golden` drives identical bytes through real
  slapd and through Olivine in-process and diffs the transcripts. It is
  green, and it has already corrected two mistakes — see §3.1.
- **`internal/schema` parses the real thing.** All 15 `.schema` files in the
  submodule load (1,133 attribute types, 85 object classes), and the parser
  reads all 464 definitions slapd itself emits from `cn=Subschema` — captured
  as testdata by `scripts/capture-subschema.sh`, which is the sharpest oracle
  short of a live comparison, since slapd's output includes the operational
  attributes hardcoded in `schema_init.c` that appear in no `.schema` file.
  84.6% coverage.
- **`internal/dn` matches slapd exactly.** All 35 cases in
  `internal/dn/testdata/normalised.txt` — captured from slapd's own
  `dnNormalize` and `dnPretty` via `slapdn`, by
  `scripts/capture-dn.sh` — agree, for both the normal and the pretty form.
  92.4% coverage, fuzzed for 12.4M executions.
- **`internal/schema` also ships the built-in schema.** `schema.Builtin`
  registers the 208 attribute types and 37 object classes slapd hardcodes in
  `schema_init.c`, derived rather than transcribed by
  `scripts/derive-builtin.sh`.
- **`internal/store` persists entries in Postgres.** Add, get, search by all
  four scopes, modify and delete, verified against Postgres 17 — `make store`
  starts a throwaway instance and runs them; plain `make test` skips them, so
  the default suite stays hermetic. See `internal/store/README.md`.
- `make lint`, `make test`, `make race`, `make build` and `make golden` all
  pass.
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
2. ~~Repository skeleton.~~ Done, `f0bf73e`.
3. ~~The BER codec, `internal/ber`.~~ Done, `b078080`.
4. ~~The protocol layer and the TLS listener.~~ Done, `59bd65f` and this
   commit.
5. ~~The golden harness, `internal/golden`.~~ Done — this commit.
6. ~~Schema subsystem.~~ Parsing and the registry done — this commit.
   Still outstanding within it: syntaxes and matching rules as *behaviour*
   (`schema_init.c`'s normalisation and comparison functions), which is where
   behaviour compatibility is actually won or lost. The definitions are
   parsed; the semantics are not implemented.
7. ~~DN handling and the Postgres store.~~ Done — this commit.
8. **Operations** — mostly done, this commit. Bind, search, add, modify,
   delete and compare are wired and golden-verified. Outstanding: **schema
   checking** (slapd refuses an entry whose objectClass is undefined; Olivine
   accepts it), modrdn, the root DSE, abandon's effect, paged results, and
   the matching-rule semantics from step 6's second half that proper
   ordering and substring matching need.
8. **Operations** — bind, search, add/modify/delete/modrdn, compare,
   abandon, root DSE. This is what unblocks most of the 113 upstream test
   scripts as harness corpus.

The plan carries the ordering beyond that, and three open questions —
whether `syncrepl.c` is ported at all, whether `cn=config` becomes a
read-only projection of the environment, and how far SASL goes beyond simple
bind over TLS — each tagged with the step it blocks.

## 3. Project State

### 3.1 Key Logic

`internal/ber` is the only implemented package. Its departures, and the
upstream behaviours that are easy to get wrong:

- **The resumable reader is not ported.**
  `libraries/liblber/io.c:473` carries a comment explaining that
  `ber_get_next` "can safely be called multiple times for the same packet"
  and resumes where it stopped. That state machine exists because slapd
  multiplexes connections over a poll loop. A goroutine per connection blocks
  on `io.ReadFull` instead, and the resumption state is dead weight. This is
  the first place the Go will look wrong to someone reading the C.
- **`ber_printf`/`ber_scanf` are not reimplemented.** Checked, and the
  format layer hides nothing: `encode.c`'s dispatcher is a pure switch in
  which every case calls a typed `ber_put_*` directly, with only `'t'` (tag
  override) and `'!'` (hook) carrying state. The tag is a parameter instead.
- **`ber_int_t` is int32, not int64.** `configure:25130-25140` resolves
  `LBER_INT_T` to `int` whenever `int` is at least 32 bits, falling back to
  `long` only otherwise — so integer contents over four octets are a parse
  error, and `MessageID` is int32, matching RFC 4511's `maxInt`. Reading
  `unsigned long` elsewhere in `lber_types.hin` and concluding 64-bit would
  have accepted messages upstream rejects.
- **Three upstream laxities are matched on purpose**, each with a test
  saying so: a zero-length integer decodes to 0 rather than failing, as does
  a non-minimal one; and non-minimal long-form lengths are accepted, so
  `0x81 0x05` and a bare `0x05` both mean five. Being stricter than upstream
  is still a divergence.
- **A zero-length *top-level* element is rejected** (`io.c:613-616`,
  ERANGE), though a zero-length element nested inside one is legal. The
  asymmetry belongs to the framing layer, so `ReadPacket` carries it and the
  `Decoder` does not.
- **Tags are packed raw octets**, not a decoded class/number pair, because
  `ldap.h:522-548` states every operation that way — `LDAP_REQ_BIND` is
  `0x60`. A decoded form would need re-packing at every comparison.
- **`ber_put_boolean` writes `0xff` for true**, not `0x01`.
- **slapd returns attribute descriptions in the capitalisation the schema
  declares**, so an entry comes back carrying `objectClass`, not
  `objectclass`. The store keeps the lower-cased form — right for matching
  and indexing — and converts on the way out. The golden harness caught this:
  every search script differed by exactly one capital letter.
- **An undefined objectClass is `invalidSyntax` (21), not
  `objectClassViolation` (65).** slapd validates the value against the
  objectClass syntax before it ever considers the class hierarchy. The whole
  table was captured from the oracle by adding deliberately bad entries:

  | failure | code | diagnostic |
  |---|---|---|
  | undefined objectClass | 21 | `objectClass: value #0 invalid per syntax` |
  | missing MUST | 65 | `object class 'person' requires attribute 'sn'` |
  | no structural class | 65 | `no structural object class provided` |
  | attribute not allowed | 65 | `attribute 'dc' not allowed` |
  | two structural classes | 65 | `invalid structural object class chain (a/b)` |
  | undefined attribute | 17 | `nosuchattr: attribute type undefined` |

- **slapd checks the schema *before* existence and before the parent.** A
  duplicate DN carrying an undefined objectClass comes back 21, not 68; a
  missing parent with the same bad class is 21, not 32.
- **An RDN value absent from the entry is accepted.** `dn: cn=g,...` with
  `cn: different` and no `cn: g` is added without complaint, which RFC 4511
  only makes a SHOULD.
- **`objectClass: domain` lives in `cosine.schema`, not `core.schema`**, which
  is how the harness fixture came to be refused by slapd and accepted by
  Olivine before any of this existed.
- **RFC 4513 5.1.2's unauthenticated bind is rejected.** A bind with a name
  and an empty password would otherwise authenticate anyone who knows a DN.
  An empty name *and* empty password is an anonymous bind and succeeds
  (5.1.1).
- **A bind against a missing entry gives `invalidCredentials`**, not
  `noSuchObject`: telling an unauthenticated caller which DNs exist is a
  disclosure.
- **StartTLS on an already-TLS connection is `operationsError`**, diagnostic
  "TLS already started" — not `unwillingToPerform`. `starttls.c:46-48`
  branches on `op->o_conn->c_is_tls != 0`, which for Olivine is always true.
  **The golden harness found this**; it had been a guess, and both the code
  and its unit test asserted the wrong code until the C was asked directly.
- **slapd silently ignores an unknown directive in a schema file.**
  `slaptest` reports success and the definition is simply absent. Verified by
  feeding the oracle a deliberately misspelled keyword: exit 0, and the
  attribute unregistered. This matters because **upstream's own
  `dsee.schema:96` says `attributeype`**, so `targetUniqueId` is missing from
  every slapd that loads that file. Olivine skips such definitions rather
  than refusing the file, and records them in `Registry.Skipped` so the
  silence is not total.
- **`dsee.schema` and `dyngroup.schema` cannot both be loaded.** Both define
  the OID macro `NetscapeRoot`, and slapd refuses a redefinition:
  `objectidentifier: "NetscapeRoot" previously defined "2.16.840.1.113730"`.
  Olivine refuses it too, so the clash stays visible instead of resolving to
  whichever file loaded last.
- **OID macros are an OpenLDAP extension**, not RFC 4512, and they nest:
  `objectIdentifier Attr Base:1` then `attributetype ( Attr:3 ... )`.
- **`msuser.schema` writes `SYNTAX` in quotes**, which the ABNF forbids and
  slapd accepts.
- **`core.schema` comments out `cn` and `name`** because `schema_init.c`
  defines them in C. A registry built from the `.schema` files alone cannot
  resolve `cn`, and every DN needs it — which is how the built-in set came to
  be derived. The commented-out definitions are not dead weight; they are a
  signal that the C owns those types.
- **Equality matching rules are inherited up the `SUP` chain.** `cn` declares
  no `EQUALITY` of its own; `caseIgnoreMatch` comes from `name`. Reading only
  an attribute's own `EQUALITY` leaves `cn` case-*sensitive*, so `CN=Foo Bar`
  normalises to `cn=Foo Bar` and never matches `cn=foo bar`. Caught by the
  captured DN corpus.
- **slapd escapes `=` in DN values** as `\3D`, though RFC 4514 2.4 does not
  require it outside the first position.
- **Escapes are always re-emitted as upper-case hex**, never the `\c` short
  form: `cn=a\,b` normalises to `cn=a\2Cb`, and an input of `\2c` comes
  back as `\2C`.
- **Normalise and pretty differ on a trailing escaped space.** `cn=trail\ `
  normalises to `cn=trail` (insignificant space dropped) but prettifies to
  `cn=trail\20` (kept, hex-escaped), because pretty does not apply the
  matching rule.
- **`;` is a legacy RDN separator** that slapd still accepts and normalises
  to `,`: `cn=a;dc=x` becomes `cn=a,dc=x`.
- **The `#hexstring` value form is rejected**, even when the hex decodes to
  well-formed BER: `cn=#0403616263` is a valid OCTET STRING and `slapdn`
  still refuses it.
- **Multi-valued RDNs are sorted**: `sn=b+cn=a` becomes `cn=a+sn=b`, in both
  forms, so two spellings of one RDN compare equal.
- **`SUBTREE` includes the base entry; `ONELEVEL` and `SUBORDINATE` do not.**
  The fall-through at `back-mdb/search.c:874-895` encodes it:
  `SUBORDINATE` — OpenLDAP's extension — is `SUBTREE` minus the base.
- **A suffix root has no parent in the database.** Nothing holds `dc=com`
  above `dc=example,dc=com`, so requiring a parent for every multi-RDN DN
  makes the tree impossible to start. The store holds declared naming
  contexts, as slapd takes from `suffix "..."`.
- **RFC 4511 4.6's no-values forms are not no-ops.** A `delete` with no
  values removes the whole attribute, and so does a `replace` with none. A
  modification list applies whole or not at all, which is why `Modify` runs
  in a transaction.
- **slapd parses the Sync control before deciding whether it supports it**,
  so a valueless Sync control draws `protocolError` "Sync control value is
  absent" rather than `unavailableCriticalExtension`. A test for unsupported
  critical controls therefore needs an OID nobody claims, not a Sync OID.
  Also found by the harness, as a bad test rather than bad code.
- **A trailing element after the operation that parses but is not the
  controls tag is silently ignored**, and the operation proceeds. Only one
  that fails to parse is an error. `get_ctrls2` (`controls.c:817-823`) sets
  `SLAPD_DISCONNECT` solely inside `if( tag == LBER_ERROR )`, then falls
  through with `sr_err` untouched — zero, which is `LDAP_SUCCESS`. Rejecting
  both would refuse messages upstream accepts.
- **A BIND abandons every operation already in flight** on that connection,
  before the operation is even allocated (`connection.c:1633-1636`).
- **Only three result codes may be sent unsolicited**: `protocolError`,
  `strongerAuthRequired`, `unavailable` (`result.c`,
  `LDAP_UNSOLICITED_ERROR`). The notice itself is an ExtendedResponse with
  message id 0.
- **Request and response tags are not a fixed offset apart.** Bind is
  0x60/0x61 and Add 0x68/0x69, but Delete is 0x4a/0x6b and ModDN 0x6c/0x6d,
  so arithmetic on the request tag is wrong for exactly the operations whose
  requests are primitive. A table, not a formula.
- **The extended *response* tags are 0x8a/0x8b** (`ldap.h:513-514`), not the
  0x80/0x81 of the request.
- **The per-connection pending-operation cap also doubles after bind**: 100
  unauthenticated, 1000 authenticated (`slap.h:145-146`), the same pattern as
  `sockbuf_max_incoming`.

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

Configuration is read from the environment, per the 12-factor departure:
`OLIVINE_LISTEN` (default `:636`, the ldaps port — there is no 389
listener), `OLIVINE_TLS_CERT` and `OLIVINE_TLS_KEY`. A missing certificate
is a configuration error, not a reason to fall back to cleartext.

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
- **syncrepl is not ported.** `servers/slapd/syncrepl.c` is 8,083 lines of
  slapd-to-slapd replication, and replication is Postgres's job here — that
  is the whole point of the database departure. The RFC 4533 Sync controls
  are answered `unavailableCriticalExtension`.

  This costs almost nothing on the client side, which is why it is safe.
  `ldapsearch` initialises `ldapsync = 0` (`clients/tools/ldapsearch.c:244`)
  and only sets it from `-E sync=ro|rp` (`:580-626`); the control is built
  only inside `if ( ldapsync )` (`:1221`). Plain `ldapsearch` never puts a
  Sync control on the wire. The whole cost of this decision is that
  `ldapsearch -E sync=...` stops working, and that is a replication-
  debugging invocation.

  Keep the `entryCSN` and `contextCSN` *attribute definitions* in the schema
  even so — a client asking for `+` operational attributes may expect them
  to exist — but do not maintain their values.
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
  `public`. Honoured in `internal/store/testdb_test.go`, and the test
  Postgres listens on 15432 rather than 5432 so it cannot be confused with a
  real instance.
- **Other projects on this machine run their own Postgres containers.**
  `scripts/postgres-down.sh` removes only the container this project named.
- **GPG signing times out regularly** (a gnome3 pinentry issue, not a code
  problem). The fix is always to retry the identical `git commit` once the
  user has unlocked the key. Never use `--no-gpg-sign`.

## 4. Dependency Map

**External Go modules** — GORM and the pgx stack arrived with the store, as
§4 predicted. `golang.org/x/crypto` is still absent, because Argon2id arrives
with bind at step 8 and a module listed before its first use is one
`go mod tidy` removes again.

- `gorm.io/gorm` + `gorm.io/driver/postgres` (+ transitive `jackc/pgx`,
  `pgpassfile`, `pgservicefile`, `puddle`, `jinzhu/inflection`, `jinzhu/now`,
  `golang.org/x/sync`, `golang.org/x/text`) — persistence. **Present.**
- `golang.org/x/crypto` — Argon2id (step 8, bind). Not yet.

The BER codec, the protocol layer, the TLS listener, the schema parser and
the DN code need nothing outside the standard library.

**External non-Go dependency**:

Podman (rootless), for the deployment containers and for the golden oracle
built from `openldap/`. Verified with Podman 5.8.3.

Two rootless-Podman traps the oracle hit, both of which present as "slapd
exited and said nothing":

- **`ldaps:///` defaults to port 636**, which an unprivileged container
  cannot bind — `daemon: bind(6) failed errno=13`. The listener URL must
  name a port above 1024.
- **`os.MkdirTemp` creates directories 0700**, and the container's user is a
  subuid of the host user, so it cannot traverse one even through a
  read-only bind mount. The generated config directory is chmodded 0755.

Readiness is a completed TLS handshake, not a successful dial: Podman's port
forwarder accepts connections before anything inside the container listens,
so dialling succeeds against a slapd that has already died. The oracle
container also deliberately omits `--rm`, because a container that exits
during startup takes its logs with it.

`openldap/` is a leaf that only the generator scripts and `make golden-build`
read. No Go package imports it.

## 5. Version Log

Most recent first.

A commit cannot record its own hash, so this log necessarily lags by one.
The newest entry is the commit before HEAD.

| Commit | Summary |
|---|---|
| `b078080` | Add `internal/ber`, the BER codec everything rests on |
| `81abfd1` | Settle replication: syncrepl not ported, Postgres replicates |
| `f0bf73e` | Stand up the repository skeleton |
| `db5fd8e` | Reconcile the docs with the actual repository state |
| `cceb99c` | Add CLAUDE.md and BOOTSTRAP.md |
| `1577993` | Add openldap submodule |
| `32aa4b7` | Commit nothing |

Working branch: `mother`. Never merge the `openldap/`-adjacent branches
into `mother`; they are read-only reference.

## 6. Testing Status

`internal/ber`: 64 tests, 83.9% statement coverage. Three fuzz targets —
`FuzzDecoder`, `FuzzReadPacket`, `FuzzRoundTrip` — run for roughly 17 million
executions in total with no panics. A malformed-length panic in the decoder
is a remote crash later, and under crash-only architecture a panic is a
restart, so the fuzzers are run rather than merely compiled.

`encoding/asn1` serves as an independent oracle for the subset where BER and
DER agree, standing in until the golden harness lands at step 5. One trap
worth knowing: `encoding/asn1` maps a Go `string` to PrintableString (tag
19), whereas an `LDAPString` is an OCTET STRING (tag 4), so a cross-check
written with `string` compares the wrong tag and fails against correct
output. Use `[]byte`.

Every other package has no tests, because it has no code. `make test`
reports "no test files" for those, which is the honest result and not a
passing suite.

The toolchain itself is verified: `scripts/check-style.sh` was checked
against a deliberately bad file to confirm it fails on both an 87-column
line and a 42-line function. A style checker that cannot fail is worse than
none.

The golden harness (plan step 5) is deliberately sequenced before schema and
the operations, so that everything from that point on is verified against the
C rather than reasoned about.
