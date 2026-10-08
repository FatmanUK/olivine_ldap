package ber

import (
	"bytes"
	"testing"
)

func TestDecodeLength(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want uint64
		n    int
		err  error
	}{
		{"short", []byte{0x05}, 5, 1, nil},
		{"short max", []byte{0x7f}, 127, 1, nil},
		{"long one", []byte{0x81, 0x80}, 128, 2, nil},
		{"long two", []byte{0x82, 0x01, 0x00}, 256, 3, nil},
		// The C accepts non-minimal long form; so must we.
		{"non-minimal", []byte{0x81, 0x05}, 5, 2, nil},
		{"indefinite", []byte{0x80}, 0, 0, ErrIndefinite},
		{"too many octets",
			[]byte{0x89, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			0, 0, ErrLengthRange},
		{"truncated", []byte{0x82, 0x01}, 0, 0, ErrTruncated},
		{"empty", nil, 0, 0, ErrTruncated},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, n, err := decodeLength(c.in)
			if wantErr(t, err, c.err) {
				return
			}
			if got != c.want || n != c.n {
				t.Fatalf("got %d/%d, want %d/%d",
					got, n, c.want, c.n)
			}
		})
	}
}

func TestDecodeTag(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want Tag
		n    int
		err  error
	}{
		{"sequence", []byte{0x30}, 0x30, 1, nil},
		{"bind request", []byte{0x60}, 0x60, 1, nil},
		{"context 0", []byte{0x80}, 0x80, 1, nil},
		{"multi-octet", []byte{0x1f, 0x21}, 0x1f21, 2, nil},
		{"truncated multi", []byte{0x1f}, 0, 0,
			ErrTruncated},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, n, err := decodeTag(c.in)
			if wantErr(t, err, c.err) {
				return
			}
			if got != c.want || n != c.n {
				t.Fatalf("got %#x/%d, want %#x/%d",
					got, n, c.want, c.n)
			}
		})
	}
}

func TestInt32(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want int32
		err  error
	}{
		// ber_decode_int returns 0 for empty contents
		// rather than failing. DER would reject this.
		{"empty is zero", nil, 0, nil},
		{"one", []byte{0x01}, 1, nil},
		{"127", []byte{0x7f}, 127, nil},
		{"128", []byte{0x00, 0x80}, 128, nil},
		{"minus one", []byte{0xff}, -1, nil},
		{"minus 128", []byte{0x80}, -128, nil},
		{"max int32", []byte{0x7f, 0xff, 0xff, 0xff},
			2147483647, nil},
		{"min int32", []byte{0x80, 0x00, 0x00, 0x00},
			-2147483648, nil},
		// Non-minimal is accepted, as in the C.
		{"non-minimal five", []byte{0x00, 0x05}, 5, nil},
		// ber_int_t is int32, so five octets is an error
		// even though it would fit an int64.
		{"five octets",
			[]byte{0x01, 0, 0, 0, 0}, 0, ErrIntRange},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Int32(c.in)
			if wantErr(t, err, c.err) {
				return
			}
			if got != c.want {
				t.Fatalf("got %d, want %d",
					got, c.want)
			}
		})
	}
}

func TestDecoderWalksSequence(t *testing.T) {
	// SEQUENCE { INTEGER 1, OCTET STRING "ab" }
	msg := []byte{
		0x30, 0x07,
		0x02, 0x01, 0x01,
		0x04, 0x02, 'a', 'b',
	}
	tag, content, err := NewDecoder(msg).Next()
	if err != nil {
		t.Fatal(err)
	}
	if tag != TagSequence {
		t.Fatalf("tag = %#x, want %#x", tag, TagSequence)
	}
	d := NewDecoder(content)
	_, c1, err := d.Next()
	if err != nil {
		t.Fatal(err)
	}
	n, err := Int32(c1)
	if err != nil || n != 1 {
		t.Fatalf("int = %d, err %v", n, err)
	}
	_, c2, err := d.Next()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c2, []byte("ab")) {
		t.Fatalf("string = %q", c2)
	}
	if !d.Done() {
		t.Fatal("expected exhausted decoder")
	}
}
