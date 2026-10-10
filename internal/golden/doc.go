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
// Upstream's own test scripts are not the corpus. An earlier
// version of this comment said they were: 113 entries under
// openldap/tests/scripts, "not something to invent". But 19 of
// those are infrastructure (conf.sh, defines.sh, start-server),
// and 66 of the remaining 94 drive an offline slap* tool —
// slapadd, slapcat, slapindex — which link slapd's backend
// directly rather than opening a socket, so nothing done at the
// protocol level makes them read a Postgres database. The
// scripts here are written instead, one per behaviour, and the
// reusable part of upstream's are the .ldif files under
// openldap/tests/data and the client invocations inside them.
//
// The tests here are behind the `golden` build tag, because
// they need a built container and are far slower than a unit
// test. `make golden` runs them; `make test` does not.
// `make golden-build` builds the image first.
package golden
