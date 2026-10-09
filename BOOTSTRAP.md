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
- **Matching rules and syntax validation are implemented.** `internal/schema`
  carries the normalizers, the comparisons and the syntax validators, and the
  golden suite compares substring, ordering, integer-ordering and spacing
  behaviour against slapd. The two hand-written `caseInsensitiveRules`
  placeholders in `internal/dn` and `internal/store` are gone.
- **Access control works and matches slapd on nine policies**, compared by
  `make golden-acl`: the same directive text is installed in `slapd.conf` and
  parsed by `internal/acl`. Levels, the disclose switch, per-attribute
  selection, `self`/`users`/`anonymous`/`dn=` subjects and `dn.subtree=`
  scoping all agree.
- **modrdn, the root DSE and `rootdn` work**, all three golden-verified.
  Subtree rename included: `back-mdb` renames a whole subtree and so does
  this.
- **The standard schema is embedded**, derived from slapd's own
  `cn=Subschema` by `scripts/derive-standard.sh`. A Go-only binary resolves
  `dc`, `ou` and `person` with no submodule, which is what lets the CI — which
  checks out without submodules — actually run the store tests.
- **There is a container.** `make pod-build` produces a ~19 MB image from
  `scratch` — a static binary and the CA bundle, no shell and no package
  manager — running as uid 10001 on port 6360. `make pod-run` smoke-tests it
  by querying the root DSE with upstream's own `ldapsearch`.
- **Search limits work**, compared against slapd by `make golden-limits`:
  size, the request-versus-administrator minimum, the exactly-at-limit edge,
  and the `rootdn` bypass.
- **Paged results work**, compared against slapd by `make golden-paged` across
  four page sizes. It is the one control Olivine implements, and the only one
  the root DSE advertises.
- **`cn=config` is writable and lives in Postgres**, visible only to the
  administrator. The settings a running server can adopt — the suffixes, the
  access policy, the root identity and the limits — are stored in the
  `config_settings` table; the environment supplies *defaults for first
  boot*. A change made through one replica reaches the others, which is what
  makes a configuration change something other than a lockstep redeploy.
- **Abandon works, and operations run concurrently per connection.** A
  spawned operation that is abandoned sends nothing at all.
- **SASL works over TLS**, which is the normal configuration and not a
  problem to be proxied around. EXTERNAL binds as the client certificate and
  PLAIN carries a DN and password; `make golden-sasl` compares EXTERNAL
  against the C, and `make pod-run` binds to the container with upstream's own
  `ldapwhoami -Y EXTERNAL`.
- **whoami (RFC 4532) is implemented**, which is what makes `ldapwhoami` work
  at all and the quickest way to see what a bind actually did.
- **GSSAPI works**, over `gokrb5` — pure Go, no libkrb5, so the scratch image
  is unchanged. `make golden-gssapi` stands up a KDC, points upstream's own
  `ldapwhoami -Y GSSAPI` at slapd and at Olivine in turn, and compares the
  DN each reports. Both answer `dn:uid=tester,cn=gssapi,cn=auth`.
- Not implemented: the ACL features listed in §3.3.
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
6. ~~Schema subsystem.~~ Done — parsing, the registry, checking, and the
   matching rules and syntax validators.
7. ~~DN handling and the Postgres store.~~ Done — this commit.
8. ~~Operations.~~ Bind, search, add, modify, delete, compare, modrdn, the
   root DSE, paged results and abandon are all done. SASL remains an open
   question — the last one.
8. **Operations** — bind, search, add/modify/delete/modrdn, compare,
   abandon, root DSE. This is what unblocks most of the 113 upstream test
   scripts as harness corpus.

The plan carries the ordering beyond that. Its three open questions are all
settled: `syncrepl.c` is not ported (Postgres replicates), `cn=config` is
writable and backed by Postgres with the environment as first-boot defaults,
and SASL goes as far as EXTERNAL and PLAIN over TLS with GSSAPI costed but
not implemented.

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
- **`sizeLimitExceeded` means there were *more* than the limit.** A search
  matching exactly the limit answers success. The entries found are returned
  alongside the overrun, not discarded.
- **The lower of the request's and the administrator's size limit wins**, and
  zero on either side means that side is unlimited rather than the smallest: a
  request for 10 against `sizelimit 2` gets 2, and so does a request for 0.
- **`rootdn` is not subject to the size limit.**
- **slapd's own defaults are 500 entries and 3600 seconds**, so an
  unconfigured directory is not unlimited.
- **Which entries a truncated search returns is not specified.** slapd
  truncates in index order and Olivine by DN, so the golden scripts for limits
  compare the result code and the count and not the set — asserting the set
  would assert something neither implementation promises. **Paged results has
  the same property**: which entries land on which page follows traversal
  order, so `make golden-paged` compares page count, page sizes and the union,
  which is everything RFC 2696 actually promises.
- **The paged cookie is opaque by RFC 2696 2, and Olivine's differs from
  slapd's on purpose.** slapd's is an index position; Olivine's names the last
  DN returned, so an entry deleted behind the cursor cannot shift the sequence
  and cause a skip or a repeat. A cookie Olivine did not issue is refused with
  `unwillingToPerform` rather than guessed at.
- **`back-mdb` renames a whole subtree.** Renaming `ou=people` with children
  beneath it answers success, not `notAllowedOnNonLeaf`. Delete refuses a
  non-leaf; ModDN does not, and assuming the two behave alike is wrong.
- **modrdn replaces the RDN attribute value.** Renaming `cn=Alice` to
  `cn=Alicia` leaves the entry carrying `cn: Alicia`. Moving only the DN
  leaves an entry whose `cn` disagrees with its own name, and a search for the
  new name finds nothing. With `deleteoldrdn` false the entry keeps both.
- **A renamed descendant keeps its own spelling.** Only the moved suffix
  changes, so `cn=Alice,ou=people` becomes `cn=Alice,ou=humans` — rebuilding
  the pretty DN from the normal form gives `cn=alice` and differs.
- **`+` returns operational attributes and only those** (RFC 3673), which is
  why slapd's `+` output carries no `objectClass` line. A plain search or `*`
  returns user attributes. Returning everything for both agrees with slapd
  only while nothing operational is stored.
- **The root DSE is base-scope only.** A one-level or subtree search from an
  empty base answers `noSuchObject`, so it is not the top of a walkable tree:
  a client enumerating the directory reads `namingContexts` and starts again.
- **An explicitly named operational attribute is returned whatever its
  usage.** slapd answers a request for `namingContexts` alone with
  `namingContexts`, though a plain search withholds it. Honouring only `+`
  leaves a client that asks by name with an empty entry — which is exactly what
  upstream's `ldapsearch` does, and how the container smoke test found it.
- **A control that is advertised must work.** A client reads
  `supportedControl` to decide what to send, so listing an unimplemented
  control is worse than listing none. Olivine advertises paged results and
  nothing else, and refuses StartTLS without advertising it.
- **Bind, unbind and abandon cannot be abandoned**, which `abandon.c:66-68`
  names explicitly. An abandon of an unknown message id does nothing at all
  (`abandon.c:49`), and an abandon never has a response of its own either way.
- **Abandon is cooperative.** `abandon.c` sets `o_abandon` and the backend
  "can periodically check this flag and abort the operation at a convenient
  time"; `result.c` then intercepts the reply. Olivine cancels a context and
  checks it between entries, the same place the time limit is checked, and
  sends nothing — not the entries already found, and not a result.
- **A bind abandons everything in flight and waits**, because the identity
  those operations were authorised under is about to change.
- **An X.509 subject and an LDAP DN run in opposite directions.** A
  certificate written `C=GB, O=Olivine, CN=client` becomes
  `cn=client,o=Olivine,c=GB`; building the DN in certificate order gives
  something that looks right and names nothing. Go's `pkix.Name.String()`
  already emits RFC 2253 order, which is the LDAP one.
- **An *empty* SASL credential is not proxy authorization.** `sasl.c:1756`
  tests `orb_cred.bv_len`, and upstream's `ldapwhoami` sends the field present
  and empty on its second round — refusing on *presence* makes a real client
  fail with "proxy authorization not supported". Found by pointing
  `ldapwhoami` at the container.
- **A client certificate is an identity, not an admission ticket.** slapd's
  `TLSVerifyClient try` verifies one if offered and serves a client that
  presents none; demanding one would lock out everyone who binds by password.
- **`rootdn` has no entry and bypasses access control.** That is what lets a
  directory be administered before it holds anything, and why `by * none` does
  not lock out the administrator.
- **Default access is read** when no `access to` clause matches at all
  (`frontend.c:99`, `be_dfltaccess = ACL_READ`), which is why anonymous
  searches work against a slapd with no ACL configuration.
- **A clause that matches with no matching `by` denies** — it does not fall
  through to the default.
- **`disclose` is the hide-or-admit switch.** Without it an unreadable entry
  answers `noSuchObject` (32); with it, `insufficientAccess` (50).
- **The hide-or-admit decision belongs to the *entry*, not the attribute.**
  Under `access to attrs=sn by * none` then `access to * by * read`, a compare
  of `sn` answers `insufficientAccess`, because the requester can already see
  the entry. Using the attribute's own level gives `noSuchObject` and differs.
- **`access to` selection is per attribute**, so one clause can hide
  `description` while a later one grants everything else.
- **A policy of `by self write by users read by * none` makes it impossible
  for anyone to bind.** At bind time the requester is still anonymous, so
  neither `self` nor `users` matches and `* none` denies `auth` on
  `userPassword`. slapd answers `invalidCredentials`. The working pattern is
  an explicit `access to attrs=userPassword by * auth`.
- **An anonymous update is refused with `strongerAuthRequired` (8)**, before
  the ACLs are consulted and regardless of a `by * write` grant: it is a
  restriction on the connection, not a judgement about the target.
- **The schema is checked before that restriction.** An anonymous add of an
  entry with an undefined objectClass answers `invalidSyntax` (21), not 8.
- **The bound DN must be the normalised form.** A client may spell its DN
  however it likes, and an unnormalised DN compares against nothing — `self`
  and `dn=` clauses then silently never match. `Bind` returns the identity so
  the backend, which has the schema, supplies it; slapd keeps `o_ndn` for the
  same reason.
- **An attribute with no ORDERING rule matches nothing under `>=` or `<=`.**
  `filterentry.c:648-658` reads the type's own `sat_ordering` and, when it is
  NULL, sets `LDAP_INAPPROPRIATE_MATCHING` and skips the value, so the search
  succeeds *empty*. `serialNumber` is the example: it declares EQUALITY and
  SUBSTR but no ORDERING. Substituting the equality rule's ordering partner —
  which `schema_init.c`'s `associated` field appears to invite — returns three
  entries where slapd returns none. That field is about indexing and
  approximate matching, not about filling in a missing rule.
- **A value of nothing but spaces normalises to a *single space*, not empty**
  (`schema_init.c:1934-1939`, and the same pattern in
  `numericStringNormalize` and `telephoneNumberNormalize`). `strings.Fields`
  gives the empty string and the entry then never matches.
- **Case folding is the only difference between the caseIgnore and caseExact
  families.** Both share `UTF8StringNormalize`; `schema_init.c:1893` picks by
  asking whether the rule is associated with `caseExactMatch`.
- **Substring fragments trim differently from whole values.** An `any`
  fragment keeps the space at both edges, `initial` keeps its trailing one,
  `final` its leading one — `schema_init.c:1909-1929`. Normalising all three
  as whole values silently drops asserted spaces.
- **`telephoneNumberNormalize` strips spaces and hyphens and does not fold
  case**, which the placeholder it replaced had wrong.
- **The Integer syntax has no normalizer; it validates instead.**
  `integerValidate` refuses a bare `-`, `-0` and leading zeros, which is why
  `integerMatch` can compare by digit count and then bytes.
- **`extensibleObject` short-circuits the permitted-attribute check
  entirely** (`schema_check.c:587-589`, "extensibleObject allows all"). MUST
  is still enforced; only what is *allowed* is skipped.
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
- **`olcSuffix` is modifiable on a real database**, and refused only on the
  frontend, monitor and config databases (`bconfig.c`, `config_suffix`). A
  writable suffix is upstream's behaviour, not an invention.
- **A modify of `objectClass` under `cn=config` is refused outright** —
  "objectclass modification disallowed", `bconfig.c:6064-6066` — because
  slapd compares the whole set before and after and will not accept a change
  to either.
- **A malformed `olcAccess` value answers `other`, not
  `unwillingToPerform`.** `aclparse.c` never sets `reply.err`, so
  `config_parse_add`'s failure falls through to `LDAP_OTHER` at
  `bconfig.c:6034`. Guessing `invalidSyntax` here would have been wrong, and
  so would guessing `unwillingToPerform` from the function's initial `rc`.
- **A second value for a single-valued setting is `constraintViolation`**,
  with the diagnostic "`<type>`: multiple values provided"
  (`modify.c:638-648`). That is a *different* code from the one an entry's
  schema check gives for the same mistake, which also answers
  `constraintViolation` but with "attribute '%s' cannot have multiple values"
  (`schema_check.c:103-116`).
- **An attribute `cn=config` has no table entry for is
  `unwillingToPerform`**, which is simply what `config_modify_internal`
  initialises `rc` to (`bconfig.c:6044`) and falls out with.
- **`{n}` prefixes are an ordering mechanism, not decoration.** slapd reads a
  leading `{n}` on an added value to place it within an ordered attribute
  (`bconfig.c:6186-6200`) and emits the index on the way out. `olcAccess`
  needs it: the first matching clause decides, so the order *is* the policy.
- **A deletion of a value that is not present is `noSuchAttribute`.**
- **A SASL GSSAPI bind is three LDAP round trips, and the middle request
  carries no credentials field.** Captured from upstream's own `ldapwhoami`
  through a logging proxy: request one is the initial context token with the
  AP-REQ, the answer is the AP-REP; request two has the mechanism name and
  *no* credentials octet string, and the answer is the security-layer offer;
  request three is the client's choice, and the answer is success with no
  credentials at all. A server that required a present-but-empty credential
  on the second step would refuse every MIT client.
- **slapd layers GSSAPI confidentiality on top of TLS by default.** A
  GSSAPI bind over `ldaps://` reported `SASL SSF: 256`, identical to the same
  bind over `ldap://`, so the second layer is not suppressed because the
  first exists. `-O maxssf=0` is what asks for no layer, and the bind then
  succeeds with the same DN.
- **Configuration DNs must be compared case-insensitively.**
  `olcDatabase={1}postgres` is mixed case, and comparing a lower-cased search
  base against the entry's own spelling silently found nothing — so a
  base-scope search or modify of the database entry answered `noSuchObject`.
  Found by the first write test that aimed at it.

### 3.2 Architecture

Package layout, mirroring the C's separation of concerns rather than its file
layout. All of these are implemented.

| Go package | Ported from |
|---|---|
| `internal/ber` | `libraries/liblber/{decode,encode,io}.c` |
| `internal/ldap` | protocol messages, RFC 4511 |
| `internal/server` | `servers/slapd/{daemon,connection}.c` |
| `internal/schema` | `servers/slapd/{at,oc,syntax,mr,schema_init}.c` |
| `internal/dn` | `servers/slapd/dn.c` |
| `internal/store` | new — Postgres/GORM, no C analogue |
| `internal/gss` | new — `sasl.c` delegates GSSAPI to Cyrus and MIT, so there is no C to port; what is ported is the observed exchange |
| `internal/golden` | new — the oracle |
| `cmd/olivined` | `servers/slapd` (the daemon entry point) |

Configuration is split in two, which is the shape the 12-factor departure
actually wants:

| | Where | Why |
|---|---|---|
| `OLIVINE_DSN`, `OLIVINE_TLS_CERT`/`_KEY`/`_CLIENT_CA`, `OLIVINE_LISTEN`, `OLIVINE_SCHEMA` | the environment, every start | needed *before* the database is reachable, or before it can be parsed |
| suffixes, access policy, root identity, search limits | `config_settings` in Postgres, projected as `cn=config` | identical across replicas, so shared state rather than per-process config |

`OLIVINE_LISTEN` defaults to `:636`, the ldaps port — there is no 389
listener. A missing certificate is a configuration error, not a reason to
fall back to cleartext. The environment variables for the second row are
read only when the database holds nothing for that setting, so a change made
over LDAP is not undone by the next deploy.

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

- **SASL over TLS is the intended pairing, not a conflict.** slapd hands the
  TLS strength and the peer certificate to its SASL layer the moment the
  handshake completes (`connection.c:1400-1419`) and then calls
  `slap_sasl_cbinding` to bind the exchange to the channel. Over `ldaps://`
  slapd advertises GSSAPI, GSS-SPNEGO and GS2-KRB5 among others, and a SASL
  PLAIN bind over `ldaps://` runs to completion. **No proxy is needed for
  SASL or GSSAPI.** What a SASL *security layer* should not do over TLS is
  negotiate its own confidentiality on top, which is a `qop` setting rather
  than an obstacle.
- **GSSAPI is implemented**, over `gokrb5`, and compared against the C by
  `make golden-gssapi`. The exchange was captured from upstream's own
  `ldapwhoami` talking to slapd through a logging proxy rather than read out
  of RFC 4752, which settled two things no reading would have: the client's
  second bind request carries **no credentials field at all** — not an empty
  one — and the whole thing is three LDAP round trips.
- **Only the no-security-layer GSSAPI option is offered.** slapd offers
  integrity and confidentiality too, and MIT's client takes confidentiality
  by default — over `ldaps://` that is a second layer of encryption inside
  the first, which the oracle was observed doing (`SASL SSF: 256` over TLS).
  Olivine is TLS-only, so there is nothing left for a SASL security layer to
  protect: it offers `0x01` alone and refuses a client that insists on more.
  Visible to a client only as `SASL SSF: 0`.
- **No acceptor subkey is sent in the AP-REP.** RFC 4121 4.1 allows either,
  and omitting it means the per-message key is the one already agreed — the
  authenticator's subkey when the client sent one, the ticket session key
  otherwise — which is one fewer secret to generate. The visible consequence
  is that the client's Wrap tokens carry no AcceptorSubkey flag.
- **The derived DN omits the realm when it is the server's own.** slapd
  composes `uid=<user>,cn=<realm>,cn=<mech>,cn=auth` in
  `slap_sasl_getdn` (`sasl.c:1957-2010`), but the realm RDN only appears
  when Cyrus passes a realm through, and it does not when the realm is the
  default. Observed: `tester@OLIVINE.TEST` against a slapd in that realm
  gives `dn:uid=tester,cn=gssapi,cn=auth`. Olivine matches, and names the
  realm when it differs — a case the single-realm harness cannot compare, so
  it is reasoned rather than verified and marked as such.
- **GSSAPI is advertised only when a keytab is configured.** slapd advertises
  it whenever Cyrus has the plugin, keytab or not, so a client can select a
  mechanism that cannot possibly succeed. `OLIVINE_KRB5_KEYTAB` is what turns
  it on, and a keytab that cannot be read fails the start rather than
  quietly disabling the mechanism.
- **A GSSAPI authorization identity is refused**, like EXTERNAL's and
  PLAIN's. slapd maps one through `authz-regexp` and `authz-to` rules that
  Olivine does not carry; honouring the request without the rules would grant
  more than was asked for.
- **gokrb5 is a client library, and the acceptor side shows it.** It can read
  an AP-REP but not write one, and it ships `NewInitiatorWrapToken` with no
  acceptor counterpart — so `internal/gss` writes the AP-REP itself and
  builds the acceptor's Wrap token, where both the flags and the key usage
  change direction. Getting either wrong fails as a bad checksum rather than
  as a type error, which is why there are unit tests for the negotiation half
  and a comparison against the C for the rest.
- **`WrapToken.SetCheckSum` does not set `EC`.** It computes the checksum and
  leaves the field claiming zero length, so a marshalled acceptor token has
  the payload where the client looks for the checksum. RFC 4121 4.2.6.2 makes
  `EC` the checksum's length on an unsealed token; `internal/gss` sets it
  after signing.
- **EXTERNAL completes in one round where slapd takes two.** slapd's
  Cyrus-backed EXTERNAL answers `saslBindInProgress` first; RFC 4422 3 allows
  either, and a conformant client loops until the result is not
  `saslBindInProgress`. Proven interoperable: upstream's `ldapwhoami -Y
  EXTERNAL` binds to Olivine in one round and reports the right DN.
- **SASL PLAIN checks `userPassword` directly.** slapd routes it through Cyrus
  SASL's own auxprop backend, so a PLAIN bind against a stock slapd answers
  "user not found: Password verification failed" even for a user whose
  `userPassword` is correct. Checking the directory is what almost everyone
  configures slapd to do eventually, and doing it by default is less
  surprising than delegating to a store Olivine does not have.

- **ACL features deliberately refused rather than approximated.**
  `filter=` selectors, `group=`/`set=`/`ssf=` subjects, the regex and expand
  DN styles, privilege sets (`=wrscxd`, `+`/`-`) and the `continue`/`break`
  controls all return a parse error. An access-control gap that silently
  matched everything would widen access, which is the wrong direction for this
  kind of failure.

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
- **`cn=config` is writable, and backed by Postgres rather than the
  environment.** This reverses an earlier decision in this repository, and
  the reversal is the point: `6804d94` made `cn=config` a read-only
  projection on the reasoning that the 12-factor departure made the
  environment the single authority. That misread 12-factor, which calls
  config what *varies between deploys*. A DSN and a certificate path vary;
  the suffixes, the access policy and the limits do not — they are identical
  across every replica, which makes them shared state, and the shared state
  store was already here and already replicated. The read-only version meant
  changing a suffix was a lockstep redeploy of every replica, which is the
  opposite of what the departure was for.

  So the split is by *when a value is needed*, not by what kind of value it
  is: anything required before the database can be reached stays
  environmental because there is nowhere else it could come from, and
  everything else lives in `config_settings`. The environment's values for
  the second group are defaults for first boot — a setting the database
  already holds wins, or a change made over LDAP would be undone by the next
  deploy.
- **Replicas poll rather than listen.** `OLIVINE_CONFIG_REFRESH` seconds
  (default 30) between re-reads. Postgres has `LISTEN`/`NOTIFY`, but a
  replica that missed a notification while reconnecting would stay wrong
  indefinitely, and a poll cannot. A failed poll keeps the configuration in
  force and logs: the database being unreachable already fails every
  operation that needs it, and publishing an empty configuration — or dying
  — because one read failed would turn a transient fault into an outage.
- **The settings are published behind an atomic pointer, not held in
  fields.** Every operation reads the suffixes, the policy, the root identity
  and the limits, and those reads happen on connection goroutines while a
  write to `cn=config` happens on another. A field written in place is a data
  race; a lock taken per read is on the path of every search. A change builds
  a whole new immutable snapshot and swaps the pointer, so a reader holds one
  consistent generation for the length of its operation and never blocks.
- **`olcRootPW` is hashed on the way in, which slapd does not do.** Upstream
  stores it exactly as given, cleartext included, and compares with
  `lutil_passwd`. Olivine hashes a bare value with Argon2id unless it already
  carries a `{SCHEME}` prefix, so the table never holds a recoverable
  credential. Visible only to something reading `olcRootPW` back, and nothing
  can: the projection withholds it, hashed or not.
- **`olcRootDN` cannot be deleted.** `cn=config` answers to the
  administrator and to nobody else, and the environment's defaults apply only
  to a setting that is *absent* at boot — so dropping it would make the
  configuration unreachable over LDAP permanently. slapd permits the
  equivalent because its `cn=config` has a `rootdn` of its own to fall back
  on. Olivine has one identity and refuses to drop it, with
  `unwillingToPerform` saying why.
- **Configuration entries cannot be added or removed**, only modified. There
  is one database, so the tree has a fixed shape — `cn=config` and
  `olcDatabase={1}postgres,cn=config` — and nothing a client could usefully
  create. slapd numbers its databases because it can hold several; the index
  is kept so a client walking the tree sees the shape it expects.
- **The in-memory setters are test helpers now.** `AddSuffix`, `SetPolicy`,
  `SetRootDN` and `SetLimits` do not persist, and a subsequent write to
  `cn=config` republishes the whole configuration from the database and
  discards them. `Bootstrap` is how a server declares its configuration. The
  doc comments say so, because the failure mode is silent.

### 3.4 Other

- **Writes to a connection are serialised by a mutex.** Operations run
  concurrently per connection, and two goroutines each writing a message would
  interleave their BER and corrupt the stream — the worst bug that concurrency
  could introduce and the cheapest to prevent. One whole message per `send`.
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
  `scripts/postgres-down.sh` removes only the container this project named,
  and `scripts/pod-run.sh` stands up its own rather than touching the test
  one.
- **`make store`'s Postgres cannot join a bridge network.** Rootless Podman
  defaults it to `pasta`, so `podman network connect` refuses it with
  `"pasta" is not supported`, and its port is published to 127.0.0.1 where a
  container cannot reach it. The container smoke test therefore runs its own
  Postgres on its own network, which is closer to a real deployment anyway.
- **An unprivileged container cannot bind a port below 1024.** The image
  listens on 6360 and the host maps 636 to it — the same trap that made the
  golden oracle fail at `ldaps:///`, which defaults to 636.
- **GPG signing times out regularly** (a gnome3 pinentry issue, not a code
  problem). The fix is always to retry the identical `git commit` once the
  user has unlocked the key. Never use `--no-gpg-sign`.

## 4. Dependency Map

**External Go modules** — GORM and the pgx stack arrived with the store, as
§4 predicted. Every dependency here is one a specific feature needed; a
module listed before its first use is one `go mod tidy` removes again.

- `gorm.io/gorm` + `gorm.io/driver/postgres` (+ transitive `jackc/pgx`,
  `pgpassfile`, `pgservicefile`, `puddle`, `jinzhu/inflection`, `jinzhu/now`,
  `golang.org/x/sync`, `golang.org/x/text`) — persistence. **Present.**
- `golang.org/x/crypto` — Argon2id, for `userPassword` and the root
  password. **Present**, since the bind work at step 8.
- `github.com/jcmturner/gokrb5/v8` + `github.com/jcmturner/gofork` (+
  transitive `aescts`, `dnsutils`, `rpc`, `goidentity`, `hashicorp/go-uuid`,
  `golang.org/x/net`) — Kerberos 5, for SASL GSSAPI. **Present.** Pure Go:
  no cgo, no libkrb5, so the scratch image is unaffected. It is a *client*
  library, which shows in two places — it can read an AP-REP but not write
  one, and it ships `NewInitiatorWrapToken` with no acceptor counterpart —
  so `internal/gss` supplies both (see §3.3).

The BER codec, the protocol layer, the TLS listener, the schema parser and
the DN code need nothing outside the standard library.

**External non-Go dependency**:

Podman (rootless), for the deployment containers and for the golden oracle
built from `openldap/`. Verified with Podman 5.8.3.

**The submodule is not needed to build, test or run.** The standard schema is
embedded (`scripts/derive-standard.sh`), so a Go-only checkout passes the whole
default suite — which is what the CI relies on, since its workflows check out
with `submodules: false`. Only the golden harness and
`internal/schema/file_test.go` read `openldap/`, and the latter skips when it
is absent.

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
| `b7f1a1e` | Run the SASL comparison in CI too |
| `cdca22c` | Add SASL over TLS: EXTERNAL, PLAIN and whoami |
| `f57466e` | Replace the placeholder CI with workflows that run the real suite |
| `9ef4dc0` | Make abandon mean something: operations now run concurrently |
| `6804d94` | Project `cn=config` read-only, closing step 10 — superseded |
| `f33149e` | Add paged results, closing step 9 |
| `adb40b5` | Add the deployment container, and fix two bugs it found |
| `69d32eb` | Add search limits, compared against slapd on five cases |
| `1edd80f` | Add modrdn, the root DSE and rootdn; embed the standard schema |
| `5a1b022` | Add a couple of missing pieces |
| `71606e0` | Add `internal/acl`: matched against slapd on nine policies |
| `1f18037` | Add matching rules and syntax validation, closing step 6 |
| `7b96eff` | Add schema checking, with slapd's exact codes |
| `ef0ade9` | Wire the operations: Olivine answers searches like slapd |
| `cddb39d` | Add `internal/store`: entries in Postgres |
| `61b6023` | Add `internal/dn`, verified against slapd's own `dnNormalize` |
| `5b536c4` | Add `internal/schema`: parse the definitions |
| `1aa12c2` | Add `internal/golden`: the oracle runs, and it was right twice |
| `72b6c47` | Add `internal/server`: it listens, dispatches and answers |
| `59bd65f` | Add `internal/ldap`: message envelope, result codes, controls |
| `c6217fc` | Record the BER findings in BOOTSTRAP.md |
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

`encoding/asn1` served as an independent oracle for the subset where BER and
DER agree, until the golden harness landed. One trap
worth knowing: `encoding/asn1` maps a Go `string` to PrintableString (tag
19), whereas an `LDAPString` is an OCTET STRING (tag 4), so a cross-check
written with `string` compares the wrong tag and fails against correct
output. Use `[]byte`.

Every package is tested. Counting top-level `Test` functions: `internal/ber`
22, `internal/ldap` 34, `internal/server` 30, `internal/schema` 23,
`internal/store` 104, `internal/acl` 7, `internal/dn` 1 (table-driven, over
a corpus derived from slapd itself), `internal/gss` 9, `internal/golden` 11,
`cmd/olivined` 4.
The store's tests skip unless `OLIVINE_TEST_DSN` or `TEST_DATABASE_URL`
names a reachable Postgres, so `make test` alone does not exercise them —
`make store` does, and the CI sets the variable so the service container is
not standing idle.

The toolchain itself is verified: `scripts/check-style.sh` was checked
against a deliberately bad file to confirm it fails on both an 87-column
line and a 42-line function. A style checker that cannot fail is worse than
none.

The golden harness (plan step 5) was deliberately sequenced before schema
and the operations, so that everything from that point on is verified
against the C rather than reasoned about. It has corrected this
implementation roughly a dozen times; the corrections are recorded in §3.1
rather than discarded.

The comparisons are `make golden` (protocol), `golden-data` (search and the
root DSE, plus `TestDataScriptsAreNotVacuous` — two servers agreeing about
silence proves nothing), `golden-acl` (nine policies), `golden-limits`,
`golden-paged`, `golden-sasl` and `golden-gssapi`.

`golden-gssapi` is shaped differently from the others, and deliberately: the
client is upstream's own `ldapwhoami`, driven at each server in turn, because
a GSSAPI *initiator* written in Go would be a second implementation of the
thing under test. It stands up a KDC in the oracle container — rootless, uid
10001, paths under `/data` and the KDC above port 1024 — issues a service
principal and keytab for each server, and compares the DN each reports.
Olivine never contacts the KDC: an acceptor decrypts the ticket with its own
keytab, which is also why its scratch image needs no `krb5.conf`.

One trap worth recording, because its error message points at the wrong
thing: podman's DNS answers with its own search domain appended, so a client
canonicalising the host asks for `ldap/<host>.dns.podman` and then derives a
realm named after it. The failure reads `Server krbtgt/DNS.PODMAN@... not
found in Kerberos database`, which looks like a KDC fault. `-N`
(`SASL_NOCANON`) is the fix, and the harness passes it. `make pod-run` is the end-to-end check: it
stands up the scratch image against a throwaway Postgres and drives it with
upstream's own `ldapsearch`, `ldapmodify` and `ldapwhoami` — including a
write to `cn=config` whose effect is then read back.
