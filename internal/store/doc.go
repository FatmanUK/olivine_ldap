// Package store persists entries in Postgres through GORM.
//
// New code: there is no C analogue. OpenLDAP's flat-file
// backends live in servers/slapd/back-*, and none of them is
// ported.
//
// Store tests must never share a database with a real world.
// The scratch schema goes in the connection string, not a
// SET search_path: GORM pools connections, so the SET reaches
// one of them and every other query lands in public.
package store
