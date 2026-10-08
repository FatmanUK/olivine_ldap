package ber

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncodeInt(t *testing.T) {
	cases := []struct {
		v    int32
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{127, []byte{0x7f}},
		{128, []byte{0x00, 0x80}},
		{255, []byte{0x00, 0xff}},
		{256, []byte{0x01, 0x00}},
		{-1, []byte{0xff}},
		{-128, []byte{0x80}},
		{-129, []byte{0xff, 0x7f}},
		{2147483647, []byte{0x7f, 0xff, 0xff, 0xff}},
		{-2147483648, []byte{0x80, 0x00, 0x00, 0x00}},
	}
	for _, c := range cases {
		got := encodeInt(c.v)
		if !bytes.Equal(got, c.want) {
			t.Errorf("encodeInt(%d) = %#v, want %#v",
				c.v, got, c.want)
		}
	}
}

func TestEncodeIntRoundTrips(t *testing.T) {
	vs := []int32{
		0, 1, -1, 127, 128, -128, -129, 255, 256,
		65535, 65536, 2147483647, -2147483648,
	}
	for _, v := range vs {
		got, err := Int32(encodeInt(v))
		if err != nil {
			t.Fatalf("%d: %v", v, err)
		}
		if got != v {
			t.Errorf("round trip %d gave %d", v, got)
		}
	}
}

func TestEncodeLength(t *testing.T) {
	cases := []struct {
		n    uint64
		want []byte
	}{
		{0, []byte{0x00}},
		{5, []byte{0x05}},
		{127, []byte{0x7f}},
		{128, []byte{0x81, 0x80}},
		{255, []byte{0x81, 0xff}},
		{256, []byte{0x82, 0x01, 0x00}},
		{65535, []byte{0x82, 0xff, 0xff}},
	}
	for _, c := range cases {
		e := NewEncoder()
		e.writeLength(c.n)
		if !bytes.Equal(e.buf, c.want) {
			t.Errorf("len %d = %#v, want %#v",
				c.n, e.buf, c.want)
		}
	}
}

func TestEncodeLengthRoundTrips(t *testing.T) {
	ns := []uint64{0, 1, 127, 128, 255, 256, 65535, 1 << 20}
	for _, n := range ns {
		e := NewEncoder()
		e.writeLength(n)
		got, used, err := decodeLength(e.buf)
		if err != nil {
			t.Fatalf("%d: %v", n, err)
		}
		if got != n || used != len(e.buf) {
			t.Errorf("round trip %d gave %d (%d octets)",
				n, got, used)
		}
	}
}

func TestEncoderNestsConstructed(t *testing.T) {
	e := NewEncoder()
	e.Begin(TagSequence)
	e.Int32(TagInteger, 1)
	e.String(TagOctetString, "ab")
	e.End()
	got, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x30, 0x07,
		0x02, 0x01, 0x01,
		0x04, 0x02, 'a', 'b',
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestEncoderNestsDeeply(t *testing.T) {
	e := NewEncoder()
	e.Begin(TagSequence)
	e.Begin(TagSequence)
	e.Null(TagNull)
	e.End()
	e.End()
	got, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x30, 0x04, 0x30, 0x02, 0x05, 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestEncoderUnbalanced(t *testing.T) {
	e := NewEncoder()
	e.Begin(TagSequence)
	if _, err := e.Bytes(); !errors.Is(err, ErrUnbalanced) {
		t.Fatalf("err = %v, want ErrUnbalanced", err)
	}
}

func TestEncoderBoolIsFF(t *testing.T) {
	// ber_put_boolean writes 0xff for true, not 0x01.
	e := NewEncoder()
	e.Bool(TagBoolean, true)
	got, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x01, 0x01, 0xff}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}
