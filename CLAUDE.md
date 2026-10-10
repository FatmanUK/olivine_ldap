# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

## What this is

A from-scratch Go reimplementation of OpenLDAP, aiming for behaviour compatibility —
with six deliberate departures: Go instead of C, TLS-only networking, Postgres/GORM
instead of a flat-file database, rootless Podman containers instead of autotools,
crash-only architecture and high-availability through the 12-factor manifesto.

**There must be exactly one plan file for this project.** It is
`~/.claude/plans/a-green-stone-in-the-socket.md`. That directory is shared across
every project on this machine, so other plan files live there too: they belong to
unrelated work and are never read or edited from here. `BOOTSTRAP.md` §2 is the
narrative of what has landed, and the plan file is what is next.

## The C reference is a submodule

This is the single most useful thing to know. The repository itself contains
only Go; the lines of OpenLDAP C that everything is ported from are the
upstream project, vendored as a submodule at `openldap/` and pinned to a
release tag:

```bash
git submodule update --init openldap       # if openldap/ is empty
git -C openldap/ describe --tags --always  # which upstream this is
```

It is read-only reference. Nothing in `openldap/` is ever edited, and the
submodule is moved to a new upstream release deliberately, not incidentally —
bumping it can be catastrophic.

**Check the C before implementing anything that claims to match upstream.**
Several behaviours in this codebase look like bugs until you read the original,
and several plausible-looking assumptions turned out to be wrong when checked.

Constrain Go source to 70 columns wide, counting a tab as 8. Keep functions
short, 40 lines at most.

## Committing

**Commit when ready.** Be aware that all commits are signed. The GPG keychain
is locked and must be unlocked by the user. Therefore the commit might fail
if the user can't unlock the keychain in time. This is intended behaviour.
When a signature fails, report this and stop work. Leave the work staged. The next
prompt is likely to request a commit and then continue work.

**Every commit is signed. Never `--no-gpg-sign`** — not to get past a failure,
not "just this once", not for a doc-only change.

**A commit message says what was *found*, not only what was done.** Divergences
are valuable output, and the message is where they are recorded for whoever reads
the history. Where upstream's behaviour differs from what its source reads like,
say so and cite the file and line.

## The golden-output harness

**This is the most useful thing in the repository. Use it.**

`internal/golden` is the oracle. It drives the same script through OpenLDAP —
built from the `openldap` submodule, in a rootless container over TCP — and
through this project in-process, then diffs the transcripts. Reading the C and
reasoning about it is guesswork; the harness answers directly, and it has
corrected this implementation about a dozen times. Those corrections are
recorded in `BOOTSTRAP.md` §3.1 rather than discarded.

```bash
make golden-build    # build the C oracle (slow, needed once)
make golden          # protocol
make golden-data     # searches over a seeded tree on both sides
make golden-acl      # access policies
make golden-limits   # search limits
make golden-paged    # paged results
make golden-sasl     # a SASL EXTERNAL bind
make golden-gssapi   # a SASL GSSAPI bind, two realms, a real KDC
```

**Reach for a comparison before reaching for the source.** Twice now, reading a
function has been less reliable than driving the thing: `slap_sasl_getdn` reads
as though a cross-realm bind yields a `cn=REALM` RDN and it does not, because
the behaviour belongs to Cyrus and slapd together. When the two cannot be
compared — because the protocol leaves something open, or the harness cannot
reach the case — say so in the code rather than implying a comparison.

Where a comparison needs a client that is not Go, drive **upstream's own
client** rather than writing a second implementation of the thing under test.
That is what `golden-gssapi` does with `ldapwhoami`, and `pod-run` with
`ldapsearch`, `ldapmodify` and `ldapwhoami`.

### Upstream's own test scripts are not a corpus this can run

An earlier version of this file said the 113 entries under
`openldap/tests/scripts` were "the corpus the harness drives". They are not,
and the correction is worth keeping:

- 19 of the 113 are not tests at all — `conf.sh`, `defines.sh`,
  `functions.sh`, `start-server`, `setup_kdc.sh` and the like.
- Of the 94 that are, **66 invoke an offline `slap*` tool** — `slapadd`,
  `slapcat`, `slapindex`. Those link slapd's backend directly instead of
  opening a socket, so no amount of protocol work makes them read a Postgres
  database. They are out of scope for the same reason `slapcat` is.
- The remaining 28 use only the network clients, and about 40 of the scripts
  overall exercise features deliberately not ported — replication, `back-sql`,
  the overlays, the proxy backends.

What *is* reusable is the material inside them: the 40 `.ldif` files under
`openldap/tests/data` as seed data, and the `ldapsearch`/`ldapmodify`
invocations as cases worth stealing. Mine them for cases; do not try to run
them.
