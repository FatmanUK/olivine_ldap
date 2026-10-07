// Package golden is the oracle.
//
// It builds a test database, drives one script through
// OpenLDAP built from the openldap submodule and through
// this project, and diffs the transcripts. The C runs in a
// rootless Podman container over TCP; Olivine runs
// in-process.
//
// Upstream ships 113 entries under openldap/tests/scripts.
// That is the corpus this harness drives; it is not
// something to invent.
//
// Not implemented yet. This is plan step 5, sequenced before
// schema and the operations so that everything after it is
// verified rather than reasoned about.
package golden
