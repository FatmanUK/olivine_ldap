package ber

import "io"

// ReadPacket reads one complete BER element from r and
// returns it whole, tag and length included.
//
// This replaces ber_get_next (liblber/io.c:481). The C's
// version is resumable mid-packet because slapd multiplexes
// connections over a poll loop; Olivine runs a goroutine per
// connection, so this blocks until the element is complete and
// the resumption state does not exist.
//
// max is the largest element accepted, and corresponds to
// sb_max_incoming. Pass MaxIncomingDefault before a
// connection has authenticated and MaxIncomingAuth after;
// slapd/slap.h:142-143 gives those as (1<<18)-1 and
// (1<<24)-1. A max of 0 means unlimited, as it does in the C.
func ReadPacket(r io.Reader, max uint64) ([]byte, error) {
	header, t, length, err := readHeader(r)
	if err != nil {
		return nil, err
	}
	// "make sure length is reasonable": io.c rejects a
	// zero-length top-level element outright, even though a
	// zero-length element nested inside one is legal.
	if length == 0 {
		return nil, ErrEmpty
	}
	if max != 0 && length > max {
		return nil, ErrTooLarge
	}
	_ = t
	out := make([]byte, len(header)+int(length))
	copy(out, header)
	if _, err := io.ReadFull(r, out[len(header):]); err != nil {
		return nil, err
	}
	return out, nil
}

// readHeader reads the tag and length octets one at a time,
// returning them verbatim along with the decoded values.
//
// Octet-at-a-time because the header is variable width and the
// contents must not be consumed: this is a framing read, not a
// buffered one. The connection layer supplies a buffered
// reader, so these are not syscalls.
func readHeader(r io.Reader) ([]byte, Tag, uint64, error) {
	header, err := readTagOctets(r)
	if err != nil {
		return nil, 0, 0, err
	}
	t, _, err := decodeTag(header)
	if err != nil {
		return nil, 0, 0, err
	}
	header, length, err := readLengthOctets(r, header)
	if err != nil {
		return nil, 0, 0, err
	}
	return header, t, length, nil
}
