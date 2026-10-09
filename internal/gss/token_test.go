package gss

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// The initial context token captured from upstream's own client,
// trimmed to its header: the application-0 tag, a length, the
// Kerberos 5 mechanism OID and the AP-REQ identifier. Taken from
// a real exchange rather than written from the RFC, so a change
// that breaks interoperability fails here.
const capturedHeader = "6082" + "02d9" +
	"06092a864886f712010202" + "0100"

func TestDecodeInitialReadsTheCapturedHeader(
	t *testing.T,
) {
	raw, err := hex.DecodeString(
		capturedHeader + "6e020304")
	if err != nil {
		t.Fatal(err)
	}
	id, inner, err := decodeInitial(raw)
	if err != nil {
		t.Fatal(err)
	}
	if id != tokIDAPReq {
		t.Errorf("token id = %x, want %x",
			id, tokIDAPReq)
	}
	want := []byte{0x6e, 0x02, 0x03, 0x04}
	if !bytes.Equal(inner, want) {
		t.Errorf("inner = %x, want %x", inner, want)
	}
}

// A token round-trips, including one long enough to need a
// multi-octet DER length — an AP-REQ always is.
func TestInitialTokenRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 127, 128, 1000} {
		inner := bytes.Repeat([]byte{0xab}, n)
		id, got, err := decodeInitial(
			encodeInitial(tokIDAPRep, inner))
		if err != nil {
			t.Fatalf("%d bytes: %v", n, err)
		}
		if id != tokIDAPRep {
			t.Errorf("%d bytes: id = %x", n, id)
		}
		if !bytes.Equal(got, inner) {
			t.Errorf("%d bytes: inner differs", n)
		}
	}
}

// Anything that is not a Kerberos 5 initial context token is
// refused rather than guessed at.
func TestDecodeInitialRefusals(t *testing.T) {
	cases := map[string]string{
		"empty":     "",
		"wrong tag": "3003060100",
		"no OID":    "60030101",
		"another mech": "60080606" +
			"2b0601050502" + "0100",
		"truncated OID":  "6003060900",
		"no token id":    "600b06092a864886f712010202",
		"bad length":     "6080",
		"short mech OID": "600306012a",
	}
	for name, h := range cases {
		raw, err := hex.DecodeString(h)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, _, err := decodeInitial(raw); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !errors.Is(err, ErrToken) {
			t.Errorf("%s: %v is not ErrToken",
				name, err)
		}
	}
}

// derLength is DER's definite form: short below 128, otherwise a
// count of octets with the high bit set.
func TestDERLength(t *testing.T) {
	cases := map[int]string{
		0:     "00",
		127:   "7f",
		128:   "8180",
		255:   "81ff",
		256:   "820100",
		65535: "82ffff",
	}
	for n, want := range cases {
		got := hex.EncodeToString(derLength(n))
		if got != want {
			t.Errorf("derLength(%d) = %s, want %s",
				n, got, want)
		}
	}
}
