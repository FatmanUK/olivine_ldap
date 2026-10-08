package ber

// decodeTag reads a packed tag from the front of b.
//
// Follows ber_tag_and_rest in liblber/decode.c: when the low
// five bits are all set the tag continues into further
// octets, each shifted in, until one has its top bit clear.
func decodeTag(b []byte) (Tag, int, error) {
	if len(b) == 0 {
		return 0, 0, ErrTruncated
	}
	t := Tag(b[0])
	if t&bigTagMask != bigTagMask {
		return t, 1, nil
	}
	for i := 1; ; i++ {
		if i >= len(b) {
			return 0, 0, ErrTruncated
		}
		// The C stops packing once another octet could
		// overflow ber_tag_t; the same bound here.
		if t > ^Tag(0)/256 {
			return 0, 0, ErrTagTooLong
		}
		t = t<<8 | Tag(b[i])
		if t&moreTagMask == 0 {
			return t, i + 1, nil
		}
	}
}

// decodeLength reads a definite length from the front of b.
//
// Follows ber_peek_element in liblber/decode.c. Short form is
// one octet under 0x80. Long form has the count of length
// octets in the low seven bits. A count of zero is the
// indefinite form, which LDAP does not use and the C rejects.
//
// Non-minimal long form is accepted, because the C accepts
// it: 0x81 0x05 and a bare 0x05 both mean five. Rejecting it
// would be stricter than upstream, which is still a
// divergence.
func decodeLength(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, ErrTruncated
	}
	first := b[0]
	if first&0x80 == 0 {
		return uint64(first), 1, nil
	}
	count := int(first & 0x7f)
	if count == 0 {
		return 0, 0, ErrIndefinite
	}
	// "Lengths that do not fit in a ber_len_t are not
	// accepted" — ber_len_t is unsigned long, so 8 octets.
	if count > 8 {
		return 0, 0, ErrLengthRange
	}
	if count >= len(b) {
		return 0, 0, ErrTruncated
	}
	var length uint64
	for _, c := range b[1 : count+1] {
		length = length<<8 | uint64(c)
	}
	return length, count + 1, nil
}
