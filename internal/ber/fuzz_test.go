package ber

import (
	"bytes"
	"testing"
)

// FuzzDecoder walks arbitrary input. Any outcome is fine
// except a panic: a malformed-length panic here is a remote
// crash later, and under crash-only architecture a panic is a
// restart.
func FuzzDecoder(f *testing.F) {
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x05})
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{0x1f, 0x1f, 0x1f, 0x1f})
	f.Add([]byte{0x02, 0x7f})
	f.Add([]byte{0x89, 1, 2, 3, 4, 5, 6, 7, 8, 9})

	f.Fuzz(func(t *testing.T, in []byte) {
		d := NewDecoder(in)
		for i := 0; i < 64 && !d.Done(); i++ {
			tag, content, err := d.Next()
			if err != nil {
				return
			}
			// Exercise the value decoders on whatever
			// contents came back.
			_, _ = Int32(content)
			_, _ = Bool(content)
			_ = String(content)
			if tag.IsConstructed() {
				_ = NewDecoder(content)
			}
		}
	})
}

// FuzzReadPacket drives the framing reader.
func FuzzReadPacket(f *testing.F) {
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x05})
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x82, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, in []byte) {
		_, _ = ReadPacket(bytes.NewReader(in),
			MaxIncomingDefault)
	})
}

// FuzzRoundTrip checks that anything the encoder produces the
// decoder reads back identically.
func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte("ab"), int32(1))
	f.Add([]byte(""), int32(-1))

	f.Fuzz(func(t *testing.T, s []byte, n int32) {
		e := NewEncoder()
		e.Begin(TagSequence)
		e.Int32(TagInteger, n)
		e.OctetString(TagOctetString, s)
		e.End()
		msg, err := e.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		_, content, err := NewDecoder(msg).Next()
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		d := NewDecoder(content)
		_, c1, err := d.Next()
		if err != nil {
			t.Fatal(err)
		}
		got, err := Int32(c1)
		if err != nil || got != n {
			t.Fatalf("int %d -> %d (%v)", n, got, err)
		}
		_, c2, err := d.Next()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(c2, s) {
			t.Fatalf("string %q -> %q", s, c2)
		}
	})
}
