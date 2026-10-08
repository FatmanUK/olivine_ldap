package ldap

import (
	"errors"

	"github.com/FatmanUK/openldap_olivine/internal/ber"
)

// OIDPagedResults is the simple paged results control, RFC 2696.
// The OID is Microsoft's; ldap.h:276 carries it as
// LDAP_CONTROL_PAGEDRESULTS.
const OIDPagedResults = "1.2.840.113556.1.4.319"

// Paged errors, with the diagnostics slapd uses verbatim.
var (
	ErrPagedAbsent = errors.New(
		"paged results control value is absent")
	ErrPagedEmpty = errors.New(
		"paged results control value is empty")
	ErrPagedDecode = errors.New(
		"paged results control could not be decoded")
	ErrPagedSize = errors.New(
		"paged results control size invalid")
	ErrPagedRepeated = errors.New(
		"paged results control specified multiple times")
)

// Paged is a paged results control value.
//
//	realSearchControlValue ::= SEQUENCE {
//		size   INTEGER (0..maxInt),
//		cookie OCTET STRING }
//
// From controls.c:1324-1331. The size is the client's requested
// page size on the way in and the server's estimate of the result
// set on the way out; slapd sends zero for the estimate.
type Paged struct {
	Size   int32
	Cookie []byte
}

// FindPaged returns the paged results control from a request.
//
// Reports whether one was present. A control given twice is a
// protocol error, which controls.c:1309-1312 checks before it
// looks at the value at all.
func FindPaged(controls []Control) (Paged, bool, error) {
	var found bool
	var out Paged
	for _, c := range controls {
		if c.OID != OIDPagedResults {
			continue
		}
		if found {
			return out, true, ErrPagedRepeated
		}
		found = true
		p, err := parsePaged(c)
		if err != nil {
			return out, true, err
		}
		out = p
	}
	return out, found, nil
}

// parsePaged decodes one control's value.
func parsePaged(c Control) (Paged, error) {
	var p Paged
	if !c.HasValue {
		return p, ErrPagedAbsent
	}
	if len(c.Value) == 0 {
		return p, ErrPagedEmpty
	}
	_, content, err := ber.NewDecoder(c.Value).Next()
	if err != nil {
		return p, ErrPagedDecode
	}
	d := ber.NewDecoder(content)
	size, err := nextInt(d)
	if err != nil {
		return p, ErrPagedDecode
	}
	// slapd checks the sign separately, with its own
	// diagnostic.
	if size < 0 {
		return p, ErrPagedSize
	}
	_, cookie, err := d.Next()
	if err != nil {
		return p, ErrPagedDecode
	}
	p.Size, p.Cookie = size, cookie
	return p, nil
}

// Encode renders a paged results control value.
func (p Paged) Encode() ([]byte, error) {
	e := ber.NewEncoder()
	e.Begin(ber.TagSequence)
	e.Int32(ber.TagInteger, p.Size)
	e.OctetString(ber.TagOctetString, p.Cookie)
	e.End()
	return e.Bytes()
}
