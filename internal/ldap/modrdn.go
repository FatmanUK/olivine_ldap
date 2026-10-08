package ldap

import "github.com/FatmanUK/openldap_olivine/internal/ber"

// ModDNRequest is RFC 4511 4.9.
type ModDNRequest struct {
	Entry        string
	NewRDN       string
	DeleteOldRDN bool
	// NewSuperior moves the entry. HasNewSuperior
	// distinguishes an absent superior from an empty one,
	// which would mean the root.
	NewSuperior    string
	HasNewSuperior bool
}

// ParseModDNRequest decodes a ModifyDNRequest body.
//
//	ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
//		entry           LDAPDN,
//		newrdn          RelativeLDAPDN,
//		deleteoldrdn    BOOLEAN,
//		newSuperior     [0] LDAPDN OPTIONAL }
func ParseModDNRequest(
	body []byte,
) (*ModDNRequest, error) {
	d := ber.NewDecoder(body)
	entry, err := nextString(d)
	if err != nil {
		return nil, err
	}
	newRDN, err := nextString(d)
	if err != nil {
		return nil, err
	}
	del, err := nextBool(d)
	if err != nil {
		return nil, err
	}
	r := &ModDNRequest{
		Entry: entry, NewRDN: newRDN, DeleteOldRDN: del,
	}
	if d.Done() {
		return r, nil
	}
	tag, content, err := d.Next()
	if err != nil {
		return nil, ErrBadRequest
	}
	if tag != TagNewSuperior {
		return nil, ErrBadRequest
	}
	r.NewSuperior = string(content)
	r.HasNewSuperior = true
	return r, nil
}
