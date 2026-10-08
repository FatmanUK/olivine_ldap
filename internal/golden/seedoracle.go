package golden

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// rootDN and rootPW match the generated slapd.conf.
const (
	rootDN = "cn=admin,dc=example,dc=com"
	rootPW = "secret"
)

// SeedLDIF renders the fixture as LDIF.
//
// Generated from the same seedLDIF the Olivine store is loaded
// from, so neither implementation can be given a tree the other
// was not. Two hand-written fixtures would drift, and a drifted
// fixture makes every later diff untrustworthy.
func SeedLDIF() string {
	var b strings.Builder
	for i, e := range seedLDIF {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "dn: %s\n", e.DN)
		for _, a := range e.Attrs {
			for _, v := range a.Values {
				fmt.Fprintf(&b, "%s: %s\n", a.Type, v)
			}
		}
	}
	return b.String()
}

// Seed loads the fixture into the oracle with ldapadd.
//
// Over LDAP rather than with slapadd, because slapadd needs the
// database offline and the container is already serving. The
// client is the one built from the submodule, so the loading path
// is upstream's own.
func (o *Oracle) Seed() error {
	if o.container == "" {
		return fmt.Errorf("oracle not running")
	}
	path := filepath.Join(o.dir, "seed.ldif")
	err := os.WriteFile(path,
		[]byte(SeedLDIF()), 0o644)
	if err != nil {
		return err
	}
	cmd := exec.Command("podman", "exec", o.container,
		"sh", "-c", ldapaddCommand())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("seeding oracle: %w: %s",
			err, out)
	}
	return nil
}

// ldapaddCommand is the shell run inside the container.
//
// LDAPTLS_REQCERT=never because the certificate is generated per
// run and is not what is under test.
func ldapaddCommand() string {
	return "LDAPTLS_REQCERT=never " +
		"/opt/openldap/bin/ldapadd " +
		"-H ldaps://localhost:" + containerPortText() + " " +
		"-x -D '" + rootDN + "' -w '" + rootPW + "' " +
		"-f /config/seed.ldif"
}

// containerPortText renders the in-container port.
func containerPortText() string {
	return fmt.Sprintf("%d", containerPort)
}
