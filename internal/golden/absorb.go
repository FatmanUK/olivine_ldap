package golden

import (
	"github.com/FatmanUK/openldap_olivine/internal/ber"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// absorb folds one response message into step, reporting
// whether the operation is finished.
func absorb(step *Step, m *ldap.Message) (bool, error) {
	if m.Op == ldap.ResSearchEntry {
		e, err := parseEntry(m.Body)
		if err != nil {
			return false, err
		}
		step.Entries = append(step.Entries, e)
		return false, nil
	}
	if m.Op == ldap.ResSearchReference {
		// A referral is not an entry and not the result.
		return false, nil
	}
	code, diag, err := parseResult(m.Body)
	if err != nil {
		return false, err
	}
	step.Result = code.String()
	step.Diagnostic = diag
	return true, nil
}

// parseResult reads the resultCode and diagnostic from an
// LDAPResult body.
func parseResult(
	body []byte,
) (ldap.ResultCode, string, error) {
	d := ber.NewDecoder(body)
	_, codeBytes, err := d.Next()
	if err != nil {
		return 0, "", err
	}
	n, err := ber.Enum(codeBytes)
	if err != nil {
		return 0, "", err
	}
	// matchedDN, then diagnosticMessage.
	if _, _, err := d.Next(); err != nil {
		return ldap.ResultCode(n), "", nil
	}
	_, diag, err := d.Next()
	if err != nil {
		return ldap.ResultCode(n), "", nil
	}
	return ldap.ResultCode(n), string(diag), nil
}

// parseEntry reads a SearchResultEntry body.
//
//	SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
//		objectName      LDAPDN,
//		attributes      PartialAttributeList }
func parseEntry(body []byte) (Entry, error) {
	var e Entry
	d := ber.NewDecoder(body)
	_, dn, err := d.Next()
	if err != nil {
		return e, err
	}
	e.DN = string(dn)

	_, attrs, err := d.Next()
	if err != nil {
		return e, err
	}
	e.Attributes, err = parseAttrs(attrs)
	return e, err
}

// parseAttrs reads a PartialAttributeList.
func parseAttrs(content []byte) ([]Attribute, error) {
	var out []Attribute
	d := ber.NewDecoder(content)
	for !d.Done() {
		_, item, err := d.Next()
		if err != nil {
			return nil, err
		}
		a, err := parseAttr(item)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// parseAttr reads one attribute and its values.
func parseAttr(item []byte) (Attribute, error) {
	var a Attribute
	d := ber.NewDecoder(item)
	_, typ, err := d.Next()
	if err != nil {
		return a, err
	}
	a.Type = string(typ)

	_, vals, err := d.Next()
	if err != nil {
		return a, err
	}
	vd := ber.NewDecoder(vals)
	for !vd.Done() {
		_, v, err := vd.Next()
		if err != nil {
			return a, err
		}
		a.Values = append(a.Values, string(v))
	}
	return a, nil
}
