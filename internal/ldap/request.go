package ldap

import (
	"context"
	"errors"

	"github.com/FatmanUK/openldap_olivine/internal/ber"
)

// ErrBadRequest reports a request body that will not decode.
var ErrBadRequest = errors.New("ldap: malformed request")

// SearchRequest is RFC 4511 4.5.1.
type SearchRequest struct {
	BaseObject   string
	Scope        Scope
	DerefAliases int32
	SizeLimit    int32
	TimeLimit    int32
	TypesOnly    bool
	Filter       Filter
	Attributes   []string
	// Context carries the operation's cancellation, so a long
	// search can be abandoned. Nil means it cannot be.
	Context context.Context
	// Controls are the request's controls, copied from the
	// enclosing message. They live here rather than being
	// looked up from the message because the backend needs them
	// — paged results is a control — and the backend is not
	// given the envelope.
	Controls []Control
}

// ParseSearchRequest decodes a SearchRequest body.
func ParseSearchRequest(
	body []byte,
) (*SearchRequest, error) {
	d := ber.NewDecoder(body)
	r := &SearchRequest{}
	if err := readSearchHeader(d, r); err != nil {
		return nil, err
	}
	tag, content, err := d.Next()
	if err != nil {
		return nil, ErrBadRequest
	}
	r.Filter, err = ParseFilter(tag, content)
	if err != nil {
		return nil, err
	}
	_, list, err := d.Next()
	if err != nil {
		return nil, ErrBadRequest
	}
	r.Attributes, err = readStringList(list)
	return r, err
}

// readSearchHeader reads the six fields before the filter.
func readSearchHeader(
	d *ber.Decoder, r *SearchRequest,
) error {
	base, err := nextString(d)
	if err != nil {
		return err
	}
	r.BaseObject = base
	nums := []*int32{
		(*int32)(&r.Scope), &r.DerefAliases,
		&r.SizeLimit, &r.TimeLimit,
	}
	for _, p := range nums {
		n, err := nextInt(d)
		if err != nil {
			return err
		}
		*p = n
	}
	only, err := nextBool(d)
	if err != nil {
		return err
	}
	r.TypesOnly = only
	return nil
}

// readStringList reads a SEQUENCE OF LDAPString.
func readStringList(content []byte) ([]string, error) {
	var out []string
	d := ber.NewDecoder(content)
	for !d.Done() {
		_, v, err := d.Next()
		if err != nil {
			return nil, ErrBadRequest
		}
		out = append(out, string(v))
	}
	return out, nil
}
