package server

import (
	"testing"

	"github.com/FatmanUK/openldap_olivine/internal/ber"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

func TestSearchSendsEntriesThenResult(t *testing.T) {
	fake := newFake()
	fake.entries = []ldap.SearchEntry{
		{DN: "cn=Alice,dc=example,dc=com"},
		{DN: "cn=Bob,dc=example,dc=com"},
	}
	_, cliTLS, addr := startWith(t, fake)
	c := dial(t, cliTLS, addr)

	if _, err := c.Write(envelope(
		t, 1, ldap.ReqSearch, searchBody(t))); err != nil {
		t.Fatal(err)
	}
	// Two SearchResultEntry messages, then SearchResultDone.
	for i := 0; i < 2; i++ {
		m := readMessage(t, c)
		if m.Op != ldap.ResSearchEntry {
			t.Fatalf("message %d op = %#x, want %#x",
				i, m.Op, ldap.ResSearchEntry)
		}
	}
	m := readMessage(t, c)
	if m.Op != ldap.ResSearchResult {
		t.Fatalf("op = %#x, want %#x",
			m.Op, ldap.ResSearchResult)
	}
	if code := resultCode(t, m); code != ldap.Success {
		t.Errorf("code = %v, want success", code)
	}
	checkSearchRequest(t, fake)
}

// checkSearchRequest verifies what the backend was handed.
func checkSearchRequest(t *testing.T, fake *fakeBackend) {
	t.Helper()
	if len(fake.searchCalls) != 1 {
		t.Fatalf("%d search calls", len(fake.searchCalls))
	}
	req := fake.searchCalls[0]
	if req.BaseObject != "dc=example,dc=com" {
		t.Errorf("base = %q", req.BaseObject)
	}
	if req.Scope != ldap.ScopeBase {
		t.Errorf("scope = %v", req.Scope)
	}
}

// The entry's attributes must survive the round trip, since a
// SET OF value is easy to encode as a SEQUENCE by accident.
func TestSearchEntryCarriesAttributes(t *testing.T) {
	fake := newFake()
	fake.entries = []ldap.SearchEntry{{
		DN: "cn=Alice,dc=example,dc=com",
		Attributes: []ldap.AttributeChange{
			{Type: "cn", Values: []string{"Alice"}},
			{Type: "sn", Values: []string{"A", "B"}},
		},
	}}
	_, cliTLS, addr := startWith(t, fake)
	c := dial(t, cliTLS, addr)
	if _, err := c.Write(envelope(
		t, 1, ldap.ReqSearch, searchBody(t))); err != nil {
		t.Fatal(err)
	}
	m := readMessage(t, c)
	got := decodeEntry(t, m)
	if got.DN != "cn=Alice,dc=example,dc=com" {
		t.Errorf("dn = %q", got.DN)
	}
	if len(got.Attributes) != 2 {
		t.Fatalf("attributes = %v", got.Attributes)
	}
	if len(got.Attributes[1].Values) != 2 {
		t.Errorf("sn values = %v",
			got.Attributes[1].Values)
	}
}

// decodeEntry reads a SearchResultEntry back out.
func decodeEntry(
	t *testing.T, m *ldap.Message,
) ldap.SearchEntry {
	t.Helper()
	d := ber.NewDecoder(m.Body)
	_, dnBytes, err := d.Next()
	if err != nil {
		t.Fatal(err)
	}
	e := ldap.SearchEntry{DN: string(dnBytes)}
	_, attrs, err := d.Next()
	if err != nil {
		t.Fatal(err)
	}
	ad := ber.NewDecoder(attrs)
	for !ad.Done() {
		_, item, err := ad.Next()
		if err != nil {
			t.Fatal(err)
		}
		e.Attributes = append(e.Attributes,
			decodeAttr(t, item))
	}
	return e
}

// decodeAttr reads one PartialAttribute.
func decodeAttr(
	t *testing.T, item []byte,
) ldap.AttributeChange {
	t.Helper()
	d := ber.NewDecoder(item)
	_, typ, err := d.Next()
	if err != nil {
		t.Fatal(err)
	}
	a := ldap.AttributeChange{Type: string(typ)}
	_, vals, err := d.Next()
	if err != nil {
		t.Fatal(err)
	}
	vd := ber.NewDecoder(vals)
	for !vd.Done() {
		_, v, err := vd.Next()
		if err != nil {
			t.Fatal(err)
		}
		a.Values = append(a.Values, string(v))
	}
	return a
}
