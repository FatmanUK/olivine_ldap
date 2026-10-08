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

To be continued.
