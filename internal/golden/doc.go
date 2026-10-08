// Package golden is the oracle.
//
// It drives one script through OpenLDAP's slapd, built from
// the pinned openldap submodule, and through Olivine, then
// diffs the transcripts. The C runs in a rootless Podman
// container over TCP; Olivine runs in-process.
//
// Reading the C and reasoning about it is guesswork. This
// answers directly, which is why plan step 5 put it before
// the schema subsystem and the operations.
//
// Upstream ships 113 entries under openldap/tests/scripts.
// That is the corpus, not something to invent.
//
// The tests here are behind the `golden` build tag, because
// they need a built container and are far slower than a unit
// test. `make golden` runs them; `make test` does not.
// `make golden-build` builds the image first.
package golden
