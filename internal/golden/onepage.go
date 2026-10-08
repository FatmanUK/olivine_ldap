package golden

import (
	"fmt"
	"io"
	"sort"

	"github.com/FatmanUK/openldap_olivine/internal/ber"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// onePage sends one paged request and reads the whole reply.
//
// Returns the DNs it carried, sorted, and the cookie to use next.
// Sorted because entry order is unspecified: what is being compared
// is which entries fell on which page, not the order within one.
func onePage(
	c io.ReadWriter, id, size int32, cookie []byte,
) ([]string, []byte, error) {
	packet, err := pagedRequest(id, size, cookie)
	if err != nil {
		return nil, nil, err
	}
	if _, err := c.Write(packet); err != nil {
		return nil, nil, err
	}
	var dns []string
	for {
		m, err := readOne(c)
		if err != nil {
			return nil, nil, err
		}
		if m.Op == ldap.ResSearchEntry {
			dn, err := entryDN(m.Body)
			if err != nil {
				return nil, nil, err
			}
			dns = append(dns, dn)
			continue
		}
		next, err := cookieOf(m)
		if err != nil {
			return nil, nil, err
		}
		sort.Strings(dns)
		return dns, next, nil
	}
}

// pagedRequest builds a subtree search carrying the control.
func pagedRequest(
	id, size int32, cookie []byte,
) ([]byte, error) {
	value, err := ldap.Paged{
		Size: size, Cookie: cookie,
	}.Encode()
	if err != nil {
		return nil, err
	}
	req := Request{
		Op: ldap.ReqSearch,
		Body: searchBody(baseDN, ldap.ScopeSubtree,
			presentFilter("objectClass"), nil),
		Controls: []ldap.Control{{
			OID:      ldap.OIDPagedResults,
			Value:    value,
			HasValue: true,
		}},
	}
	return req.Encode(id)
}

// readOne reads a single message.
func readOne(c io.Reader) (*ldap.Message, error) {
	packet, err := ber.ReadPacket(c, ber.MaxIncomingAuth)
	if err != nil {
		return nil, err
	}
	return ldap.ParseMessage(packet)
}

// entryDN reads the DN from a SearchResultEntry.
func entryDN(body []byte) (string, error) {
	_, dn, err := ber.NewDecoder(body).Next()
	if err != nil {
		return "", err
	}
	return string(dn), nil
}

// cookieOf pulls the cookie out of a result's controls.
//
// A result with no paged control ends the walk, which is what a
// server does when it has nothing more to say.
func cookieOf(m *ldap.Message) ([]byte, error) {
	paged, found, err := ldap.FindPaged(m.Controls)
	if err != nil {
		return nil, fmt.Errorf(
			"response control: %w", err)
	}
	if !found {
		return nil, nil
	}
	return paged.Cookie, nil
}
