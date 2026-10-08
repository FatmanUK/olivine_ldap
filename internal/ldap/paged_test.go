package ldap

import (
	"errors"
	"testing"

	"github.com/FatmanUK/openldap_olivine/internal/ber"
)

// pagedControl builds a control carrying a paged value.
func pagedControl(size int32, cookie []byte) Control {
	value, err := Paged{Size: size, Cookie: cookie}.Encode()
	if err != nil {
		panic(err)
	}
	return Control{
		OID: OIDPagedResults, Value: value, HasValue: true,
	}
}

func TestPagedRoundTrip(t *testing.T) {
	got, found, err := FindPaged([]Control{
		pagedControl(25, []byte("abc")),
	})
	if err != nil || !found {
		t.Fatalf("found = %v, err = %v", found, err)
	}
	if got.Size != 25 {
		t.Errorf("size = %d, want 25", got.Size)
	}
	if string(got.Cookie) != "abc" {
		t.Errorf("cookie = %q", got.Cookie)
	}
}

func TestPagedAbsentWhenNoControl(t *testing.T) {
	_, found, err := FindPaged(nil)
	if found || err != nil {
		t.Errorf("found = %v, err = %v", found, err)
	}
}

// slapd distinguishes these four, each with its own diagnostic,
// and checks the repeat before it looks at any value
// (controls.c:1309-1346).
func TestPagedErrors(t *testing.T) {
	cases := []struct {
		name string
		in   []Control
		want error
	}{
		{"repeated", []Control{
			pagedControl(1, nil),
			pagedControl(1, nil),
		}, ErrPagedRepeated},
		{"absent value", []Control{{
			OID: OIDPagedResults,
		}}, ErrPagedAbsent},
		{"empty value", []Control{{
			OID: OIDPagedResults, HasValue: true,
			Value: []byte{},
		}}, ErrPagedEmpty},
		{"undecodable", []Control{{
			OID: OIDPagedResults, HasValue: true,
			Value: []byte{0x30, 0x82},
		}}, ErrPagedDecode},
		{"negative size", []Control{
			pagedControl(-1, nil),
		}, ErrPagedSize},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := FindPaged(c.in)
			if !errors.Is(err, c.want) {
				t.Errorf("err = %v, want %v",
					err, c.want)
			}
		})
	}
}

// A response carrying controls must still parse as an
// LDAPMessage, with the controls where a client looks for them.
func TestResultWithControlsRoundTrips(t *testing.T) {
	packet, err := EncodeResultWithControls(
		7, ResSearchResult,
		Result{Code: Success},
		[]Control{pagedControl(0, []byte("cursor"))})
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseMessage(packet)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != 7 || m.Op != ResSearchResult {
		t.Fatalf("id = %d, op = %#x", m.ID, m.Op)
	}
	paged, found, err := FindPaged(m.Controls)
	if err != nil || !found {
		t.Fatalf("found = %v, err = %v", found, err)
	}
	if string(paged.Cookie) != "cursor" {
		t.Errorf("cookie = %q", paged.Cookie)
	}
}

// A result with no controls omits the element rather than sending
// an empty sequence, which is what slapd does.
func TestResultWithoutControlsOmitsThem(t *testing.T) {
	packet, err := EncodeResult(
		1, ResSearchResult, Result{Code: Success})
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseMessage(packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Controls) != 0 {
		t.Errorf("controls = %v", m.Controls)
	}
	// And the envelope holds exactly two elements.
	_, content, err := ber.NewDecoder(packet).Next()
	if err != nil {
		t.Fatal(err)
	}
	d := ber.NewDecoder(content)
	for i := 0; i < 2; i++ {
		if _, _, err := d.Next(); err != nil {
			t.Fatal(err)
		}
	}
	if !d.Done() {
		t.Error("a third element follows the operation")
	}
}
