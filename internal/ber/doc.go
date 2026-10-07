// Package ber implements the subset of BER/DER that LDAP uses.
//
// Ported from the C reference in the openldap submodule:
// libraries/liblber/{decode,encode,io}.c.
//
// Two deliberate departures from the C, recorded in
// BOOTSTRAP.md 3.1:
//
// The resumable reader is not ported. liblber/io.c:473
// documents ber_get_next as safe to call repeatedly for one
// packet, resuming where it stopped. That state machine
// exists because slapd multiplexes connections over a poll
// loop. Olivine runs a goroutine per connection and blocks
// on io.ReadFull, so the resumption state is dead weight.
//
// ber_printf and ber_scanf are not reimplemented. Their
// variadic format language is replaced by typed encode and
// decode against the message types in internal/ldap. Check
// encode.c for on-the-wire behaviour hidden in the format
// layer before discarding any of it.
package ber
