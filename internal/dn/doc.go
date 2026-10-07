// Package dn parses and normalises distinguished names.
//
// Ported from servers/slapd/dn.c in the openldap submodule.
//
// This lands before internal/store, because the store's keys
// depend on the normal form this package produces.
package dn
