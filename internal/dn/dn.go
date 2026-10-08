// Package dn parses, normalises and prettifies distinguished
// names.
//
// Ported from servers/slapd/dn.c and
// libraries/libldap/getdn.c. Verified against slapd's own
// dnNormalize and dnPretty through slapdn, captured by
// scripts/capture-dn.sh into testdata: every rule below is
// observed behaviour, not a reading of RFC 4514.
//
// This lands before internal/store, because the store's keys
// are normalised DNs.
package dn

import (
	"errors"
	"strings"
)

var (
	ErrEmpty       = errors.New("dn: empty")
	ErrSyntax      = errors.New("dn: invalid syntax")
	ErrEmptyValue  = errors.New("dn: empty attribute value")
	ErrUnknownAttr = errors.New(
		"dn: unknown attribute type")
	ErrBinaryValue = errors.New(
		"dn: hex-encoded value not accepted")
)

// AVA is one attributeTypeAndValue.
type AVA struct {
	// Type is as written, before schema resolution.
	Type string
	// Value is the unescaped value.
	Value string
}

// RDN is one relative distinguished name: one or more AVAs
// joined by '+'.
type RDN []AVA

// DN is a sequence of RDNs, most specific first.
type DN []RDN

// String renders the DN with RFC 4514 escaping, without
// consulting the schema. Normalise and Pretty are what match
// slapd; this is for diagnostics.
func (d DN) String() string {
	parts := make([]string, 0, len(d))
	for _, rdn := range d {
		parts = append(parts, rdn.String())
	}
	return strings.Join(parts, ",")
}

// String renders one RDN.
func (r RDN) String() string {
	parts := make([]string, 0, len(r))
	for _, ava := range r {
		parts = append(parts,
			ava.Type+"="+escape(ava.Value))
	}
	return strings.Join(parts, "+")
}
