package ber

// Int32 decodes two's-complement integer contents.
//
// Follows ber_decode_int in liblber/decode.c, including two
// laxities that are not DER:
//
// Zero-length contents decode to 0 rather than failing. DER
// requires at least one octet; the C's `if (len)` falls
// through to *num = 0.
//
// Non-minimal encodings are accepted: 0x00 0x05 decodes to 5
// just as a bare 0x05 does.
//
// Contents longer than four octets are rejected, because
// ber_int_t is int32 — see maxIntLen.
func Int32(b []byte) (int32, error) {
	if len(b) > maxIntLen {
		return 0, ErrIntRange
	}
	if len(b) == 0 {
		return 0, nil
	}
	// Sign-extend the leading octet, then shift the rest in.
	n := int32(int8(b[0]))
	for _, c := range b[1:] {
		n = int32(uint32(n)<<8 | uint32(c))
	}
	return n, nil
}

// Enum decodes ENUMERATED contents, which BER encodes exactly
// as INTEGER.
func Enum(b []byte) (int32, error) {
	return Int32(b)
}

// Bool decodes boolean contents.
//
// Any non-zero octet is true, matching ber_get_boolean, which
// routes through ber_decode_int and tests != 0. A multi-octet
// boolean is therefore accepted if it fits an int32.
func Bool(b []byte) (bool, error) {
	n, err := Int32(b)
	if err != nil {
		return false, ErrBadBool
	}
	return n != 0, nil
}

// String returns octet-string contents as a string. LDAP
// strings are UTF-8 on the wire but are not validated here:
// the C does not validate at this layer either, and syntax
// checking belongs to internal/schema.
func String(b []byte) string {
	return string(b)
}
