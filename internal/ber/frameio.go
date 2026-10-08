package ber

import "io"

// readByte reads exactly one octet.
func readByte(r io.Reader) (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

// readTagOctets reads a complete packed tag, however many
// octets it spans, and returns them verbatim.
func readTagOctets(r io.Reader) ([]byte, error) {
	first, err := readByte(r)
	if err != nil {
		return nil, err
	}
	out := []byte{first}
	if Tag(first)&bigTagMask != bigTagMask {
		return out, nil
	}
	t := Tag(first)
	for {
		if t > ^Tag(0)/256 {
			return nil, ErrTagTooLong
		}
		c, err := readByte(r)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		t = t<<8 | Tag(c)
		if t&moreTagMask == 0 {
			return out, nil
		}
	}
}

// readLengthOctets reads the definite length following the
// tag, appending the octets read to header.
func readLengthOctets(
	r io.Reader, header []byte,
) ([]byte, uint64, error) {
	first, err := readByte(r)
	if err != nil {
		return nil, 0, err
	}
	header = append(header, first)
	if first&0x80 == 0 {
		return header, uint64(first), nil
	}
	count := int(first & 0x7f)
	if count == 0 {
		return nil, 0, ErrIndefinite
	}
	if count > 8 {
		return nil, 0, ErrLengthRange
	}
	var length uint64
	for i := 0; i < count; i++ {
		c, err := readByte(r)
		if err != nil {
			return nil, 0, err
		}
		header = append(header, c)
		length = length<<8 | uint64(c)
	}
	return header, length, nil
}
