package ber

// encodeInt returns minimal-length two's-complement contents
// for v, as ber_put_int_or_enum does in liblber/encode.c: it
// emits octets from the bottom up and stops once the top bit
// of the leading octet is the sign bit.
func encodeInt(v int32) []byte {
	sign := byte(0)
	u := uint32(v)
	if v < 0 {
		sign = 0xff
		u = ^u
	}
	var out []byte
	for {
		out = append(out, sign^byte(u))
		if u < 0x80 {
			break
		}
		u >>= 8
	}
	// Built little-endian; BER is big-endian.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// writeTag appends a packed tag, most significant octet
// first.
func (e *Encoder) writeTag(t Tag) {
	var octets [8]byte
	n := 0
	for {
		octets[n] = byte(t)
		n++
		t >>= 8
		if t == 0 {
			break
		}
	}
	for i := n - 1; i >= 0; i-- {
		e.buf = append(e.buf, octets[i])
	}
}

// writeLength appends a definite length in minimal form, as
// ber_prepend_len does: short form under 0x80, otherwise the
// octet count with its top bit set, then the octets.
func (e *Encoder) writeLength(n uint64) {
	if n < 0x80 {
		e.buf = append(e.buf, byte(n))
		return
	}
	var octets [8]byte
	i := 0
	for n > 0 {
		octets[i] = byte(n)
		i++
		n >>= 8
	}
	e.buf = append(e.buf, byte(0x80|i))
	for j := i - 1; j >= 0; j-- {
		e.buf = append(e.buf, octets[j])
	}
}
