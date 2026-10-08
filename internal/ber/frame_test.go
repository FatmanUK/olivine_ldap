package ber

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestReadPacket(t *testing.T) {
	msg := []byte{0x30, 0x03, 0x02, 0x01, 0x05}
	got, err := ReadPacket(bytes.NewReader(msg), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %#v, want %#v", got, msg)
	}
}

func TestReadPacketStopsAtElementEnd(t *testing.T) {
	// Two packets back to back: the first read must take
	// only the first, leaving the second for the next read.
	first := []byte{0x30, 0x03, 0x02, 0x01, 0x05}
	second := []byte{0x30, 0x02, 0x05, 0x00}
	r := bytes.NewReader(append(append([]byte{},
		first...), second...))

	got, err := ReadPacket(r, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("first = %#v, want %#v", got, first)
	}
	got, err = ReadPacket(r, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, second) {
		t.Fatalf("second = %#v, want %#v", got, second)
	}
}

func TestReadPacketLongForm(t *testing.T) {
	content := bytes.Repeat([]byte{0xaa}, 300)
	msg := append([]byte{0x30, 0x82, 0x01, 0x2c}, content...)
	got, err := ReadPacket(bytes.NewReader(msg), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(msg) {
		t.Fatalf("len = %d, want %d", len(got), len(msg))
	}
}

func TestReadPacketRejects(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		max  uint64
		err  error
	}{
		// io.c rejects a zero-length top-level element,
		// though a nested one is legal.
		{"zero length", []byte{0x30, 0x00}, 0, ErrEmpty},
		{"indefinite", []byte{0x30, 0x80}, 0,
			ErrIndefinite},
		{"over max",
			[]byte{0x30, 0x05, 1, 2, 3, 4, 5}, 4,
			ErrTooLarge},
		{"truncated contents",
			[]byte{0x30, 0x05, 1, 2}, 0,
			io.ErrUnexpectedEOF},
		{"empty reader", nil, 0, io.EOF},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := bytes.NewReader(c.in)
			_, err := ReadPacket(r, c.max)
			wantErr(t, err, c.err)
		})
	}
}

func TestReadPacketLimitIsExact(t *testing.T) {
	// A message exactly at the limit is accepted; one octet
	// over is not.
	msg := []byte{0x30, 0x04, 1, 2, 3, 4}
	if _, err := ReadPacket(
		bytes.NewReader(msg), 4); err != nil {
		t.Fatalf("at limit: %v", err)
	}
	if _, err := ReadPacket(
		bytes.NewReader(msg), 3); !errors.Is(
		err, ErrTooLarge) {
		t.Fatalf("over limit: err = %v", err)
	}
}

func TestIncomingLimits(t *testing.T) {
	// slapd/slap.h:142-143.
	if MaxIncomingDefault != 262143 {
		t.Errorf("default = %d, want 262143",
			MaxIncomingDefault)
	}
	if MaxIncomingAuth != 16777215 {
		t.Errorf("auth = %d, want 16777215",
			MaxIncomingAuth)
	}
}
