package ber

import (
	"encoding/asn1"
	"testing"
)

// The golden harness (plan step 5) is the real oracle, but it
// does not exist yet. encoding/asn1 is an independent
// implementation and agrees with BER wherever DER does, so it
// checks the encoder's minimal-form output for free.
//
// Only the agreeing subset is testable this way: DER rejects
// the laxities ber_decode_int allows (zero-length and
// non-minimal integers), which is why those are covered by
// the hand-written cases instead.
//
// Note that encoding/asn1 maps a Go string to PrintableString
// (tag 19), whereas an LDAPString is an OCTET STRING (tag 4).
// Cross-checks here therefore use []byte, which asn1 does map
// to OCTET STRING. Marshalling a string instead silently
// compares the wrong tag.

func TestEncoderAgreesWithASN1OnIntegers(t *testing.T) {
	vs := []int32{
		0, 1, -1, 127, 128, -128, -129, 255, 256,
		32767, 32768, 65535, 65536,
		2147483647, -2147483648,
	}
	for _, v := range vs {
		want, err := asn1.Marshal(int64(v))
		if err != nil {
			t.Fatal(err)
		}
		e := NewEncoder()
		e.Int32(TagInteger, v)
		got, err := e.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("%d: got %#v, asn1 %#v",
				v, got, want)
		}
	}
}

func TestASN1ReadsOurSequences(t *testing.T) {
	type seq struct {
		N int
		S []byte
	}
	e := NewEncoder()
	e.Begin(TagSequence)
	e.Int32(TagInteger, 42)
	e.String(TagOctetString, "olivine")
	e.End()
	msg, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	var out seq
	rest, err := asn1.Unmarshal(msg, &out)
	if err != nil {
		t.Fatalf("asn1 rejected our output: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("%d trailing octets", len(rest))
	}
	if out.N != 42 || string(out.S) != "olivine" {
		t.Fatalf("got %+v", out)
	}
}

func TestWeReadASN1Output(t *testing.T) {
	type seq struct {
		N int
		S []byte
	}
	msg, err := asn1.Marshal(
		seq{N: 42, S: []byte("olivine")})
	if err != nil {
		t.Fatal(err)
	}
	tag, content, err := NewDecoder(msg).Next()
	if err != nil {
		t.Fatalf("we rejected asn1 output: %v", err)
	}
	if tag != TagSequence {
		t.Fatalf("tag = %#x", tag)
	}
	d := NewDecoder(content)
	_, c1, err := d.Next()
	if err != nil {
		t.Fatal(err)
	}
	n, err := Int32(c1)
	if err != nil || n != 42 {
		t.Fatalf("int = %d (%v)", n, err)
	}
	_, c2, err := d.Next()
	if err != nil {
		t.Fatal(err)
	}
	if String(c2) != "olivine" {
		t.Fatalf("string = %q", c2)
	}
}

// Long-form lengths are where an off-by-one hides, so check a
// payload that forces two length octets.
func TestASN1AgreesOnLongForm(t *testing.T) {
	long := make([]byte, 300)
	for i := range long {
		long[i] = byte('a' + i%26)
	}
	want, err := asn1.Marshal(long)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEncoder()
	e.OctetString(TagOctetString, long)
	got, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("long form differs:\n got %#v\nwant %#v",
			got[:6], want[:6])
	}
}
