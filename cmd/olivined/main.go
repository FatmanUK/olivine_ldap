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
  OLIVINE_TLS_CLIENT_CA
                     authorities that may issue client
                     certificates. With it the server requests
                     one and verifies it, and a SASL EXTERNAL
                     bind can use it as an identity; a client
                     presenting none is still served
  OLIVINE_SIZELIMIT  maximum entries per search (default 500,
                     as slapd's sizelimit)
  OLIVINE_TIMELIMIT  maximum seconds per search (default 3600)
  OLIVINE_CONFIG_REFRESH
                     seconds between re-reads of cn=config, so a
                     change made through one replica reaches the
                     others (default 30; 0 disables it)`)
	usageNotes()
}

// usageNotes explains which of the variables above are only the
// first boot's defaults, because that is the part an operator
// gets wrong: setting OLIVINE_SUFFIX on a directory that already
// has one does nothing at all.
func usageNotes() {
	fmt.Fprintln(os.Stderr, `
The settings above that a running server can adopt — the
suffixes, the access policy, the root identity and the limits —
are *defaults for first boot*. They are stored in the database
on the first start and read back from it afterwards, so they can
be changed over LDAP by modifying cn=config and the change
applies to every replica. What is needed before the database can
be reached — the DSN, the TLS material, the listen address —
has nowhere else to come from and is read from the environment
every time.

TLS is mandatory. There is no cleartext listener and no
STARTTLS, so a missing certificate is a configuration error
rather than a reason to fall back.`)
}
