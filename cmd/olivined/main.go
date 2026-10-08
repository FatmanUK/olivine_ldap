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
	"log"
	"os"
)

// version is overridden at link time by the Makefile.
var version = "dev"

func main() {
	showVersion := flag.Bool(
		"version", false, "print version and exit")
	hash := flag.String("hash", "",
		"hash a password for OLIVINE_ROOT_PASSWORD_HASH "+
			"and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("olivined %s\n", version)
		return
	}
	if *hash != "" {
		printHash(*hash)
		return
	}

	cfg, err := configFromEnv()
	if err != nil {
		log.Printf("olivined: %v", err)
		usage()
		os.Exit(1)
	}
	if err := run(cfg); err != nil {
		// Crash-only: report and die. There is no attempt
		// to repair state or resume.
		log.Fatalf("olivined: %v", err)
	}
}

// usage names the environment the daemon reads. Configuration
// comes from the environment, not a slapd.conf — see the
// 12-factor departure in BOOTSTRAP.md.
func usage() {
	fmt.Fprintln(os.Stderr, `
Configuration comes from the environment:

  OLIVINE_LISTEN     listen address (default :636)
  OLIVINE_TLS_CERT   certificate file (required)
  OLIVINE_TLS_KEY    private key file (required)
  OLIVINE_DSN        Postgres connection string; without it
                     every operation is unwillingToPerform
  OLIVINE_SUFFIX     naming contexts, colon-separated
  OLIVINE_SCHEMA     extra .schema files, colon-separated
  OLIVINE_ACL_FILE   access directives in slapd.conf syntax;
                     without it, read on everything, which is
                     what slapd defaults to
  OLIVINE_ROOT_DN    administrative identity, as slapd's rootdn:
                     it needs no entry and bypasses access
                     control
  OLIVINE_ROOT_PASSWORD_HASH
                     its password, already hashed. Use
                     "olivined -hash <password>" to make one; a
                     plaintext credential in the environment is
                     visible to ps and to a container inspect

TLS is mandatory. There is no cleartext listener and no
STARTTLS, so a missing certificate is a configuration error
rather than a reason to fall back.`)
}
