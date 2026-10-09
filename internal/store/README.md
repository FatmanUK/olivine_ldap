# internal/store

Entries in Postgres, through GORM. New code: OpenLDAP's
flat-file backends live in `servers/slapd/back-*` and none of
them is ported.

## Running the tests

They need a Postgres instance and **skip** without one, so
`make test` stays hermetic:

```bash
make store          # starts a throwaway Postgres, runs them
make postgres-down  # removes it
```

`make store` sets `OLIVINE_TEST_DSN`; the tests skip when it is
unset. The container is bound to localhost on port 15432, not
5432, so it cannot be confused with a real instance. Other
projects on this machine run their own Postgres containers;
`scripts/postgres-down.sh` removes only the one this project
named.

## The scratch-schema rule

Each test gets a Postgres schema named after it, created and
dropped around the test, and **the schema goes in the connection
string** — never a `SET search_path`.

GORM pools connections. A `SET` reaches whichever connection
happened to run it, and every other query lands in `public`, so
the tests quietly write to a real world. `BOOTSTRAP.md` §3.4
records this; it was paid for in blood.

## Why the DN is stored three times

| Column     | Question it answers              |
|------------|----------------------------------|
| `dn`       | identity, and the unique key     |
| `pretty_dn`| what to hand back to a client    |
| `rev_dn`   | what is in this subtree          |

`rev_dn` is the departure worth knowing about. `back-mdb` keeps
a subtree count beside each entry's ID
(`back-mdb/dn2id.c:40`) and walks parents. Postgres has no such
structure, and the obvious translation —
`dn LIKE '%,' || base` — cannot use an index, because the
wildcard leads. Reversing the RDNs turns "is under" into a
prefix test, which a btree index serves:
`cn=x,dc=example,dc=com` is stored as
`dc=com,dc=example,cn=x`, so everything under
`dc=example,dc=com` shares the prefix `dc=com,dc=example`.

The trailing separator in the `LIKE` pattern is not decoration:
without it, `dc=com,dc=example` also matches
`dc=com,dc=examplecorp`, and a sibling naming context leaks into
the subtree. There is a test for exactly that.

## Suffixes

A store holds declared naming contexts, as slapd takes from
`suffix "dc=example,dc=com"`. They matter twice: an entry whose
DN *is* a suffix has no parent in the database and must still be
addable (nothing holds `dc=com`), and a DN under no suffix does
not belong here at all.

They are configuration, so they live in `config_settings` with
everything else `cn=config` projects — `Bootstrap` seeds them
from the environment on a first start and reads them back
afterwards. `AddSuffix` is an in-memory override for the tests
and does not persist: a write to `cn=config` republishes the
whole configuration from the database and would discard it.

## The configuration table

| Column  | Holds                                       |
|---------|---------------------------------------------|
| `entry` | which `cn=config` entry the value is on     |
| `key`   | the attribute, lower-cased                  |
| `seq`   | the value's position within that attribute  |
| `value` | the value                                   |

A row per value, because LDAP attributes are multi-valued, and
`seq` because `olcAccess` is *ordered* — the first matching
clause decides, so the order is the policy. `(entry, key, seq)`
is unique, which is what makes two replicas seeding at once
harmless: the loser's inserts conflict and are dropped.
