// Command olivined is the Olivine LDAP server daemon.
//
// It answers to servers/slapd in the openldap submodule. The
// name follows the C's daemon convention (slapd, lloadd)
// rather than reusing slapd, because the two are not drop-in
// substitutes: Olivine is TLS-only and configured from the
// environment, so anything invoking slapd with a slapd.conf
// would fail in confusing ways.
package main

import (
	"flag"
	"fmt"
	"os"
)

// version is overridden at link time by the Makefile.
var version = "dev"

func main() {
	showVersion := flag.Bool(
		"version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("olivined %s\n", version)
		return
	}

	fmt.Fprintln(os.Stderr,
		"olivined: not implemented yet")
	fmt.Fprintln(os.Stderr,
		"The listener is plan step 4; the BER codec it "+
			"rests on is step 3.")
	os.Exit(1)
}
