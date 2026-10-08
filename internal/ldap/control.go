package ldap

import "github.com/FatmanUK/openldap_olivine/internal/ber"

// Sync control OIDs, from RFC 4533. They are recognised only
// to be refused: syncrepl is not ported, because replication
// is Postgres's job. See BOOTSTRAP.md 3.3.
const (
	OIDSyncRequest = "1.3.6.1.4.1.4203.1.9.1.1"
	OIDSyncState   = "1.3.6.1.4.1.4203.1.9.1.2"
	OIDSyncDone    = "1.3.6.1.4.1.4203.1.9.1.3"
)

// parseControlList decodes the SEQUENCE OF Control that
// follows an operation.
//
//	Control ::= SEQUENCE {
//		controlType             LDAPOID,
//		criticality             BOOLEAN DEFAULT FALSE,
//		controlValue            OCTET STRING OPTIONAL }
func parseControlList(content []byte) ([]Control, error) {
	var out []Control
	d := ber.NewDecoder(content)
	for !d.Done() {
		_, item, err := d.Next()
		if err != nil {
			return nil, ErrBadControls
		}
		c, err := parseControl(item)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// parseControl decodes one Control's contents.
func parseControl(item []byte) (Control, error) {
	var c Control
	d := ber.NewDecoder(item)

	_, oid, err := d.Next()
	if err != nil {
		return c, ErrBadControls
	}
	c.OID = string(oid)

	if d.Done() {
		return c, nil
	}
	tag, next, err := d.Next()
	if err != nil {
		return c, ErrBadControls
	}
	// criticality is optional and defaults to FALSE, so the
	// next element may be either it or the value.
	if tag == ber.TagBoolean {
		c.Critical, err = ber.Bool(next)
		if err != nil {
			return c, ErrBadControls
		}
		if d.Done() {
			return c, nil
		}
		if _, next, err = d.Next(); err != nil {
			return c, ErrBadControls
		}
	}
	c.Value, c.HasValue = next, true
	return c, nil
}

// IsCriticalUnsupported reports whether cs carries a control
// that is both critical and unknown to this server. RFC 4511
// 4.1.11 requires such an operation to fail with
// unavailableCriticalExtension rather than be ignored.
func IsCriticalUnsupported(cs []Control) (string, bool) {
	for _, c := range cs {
		if c.Critical && !supported[c.OID] {
			return c.OID, true
		}
	}
	return "", false
}

// supported lists the control OIDs this server implements.
// Empty for now: the controls arrive with the operations at
// plan step 8, and the Sync controls never will.
var supported = map[string]bool{}
