package ber

// Decoder walks the elements of one complete BER buffer.
//
// It decodes from a complete buffer rather than a stream.
// liblber/io.c:473 documents ber_get_next as resumable across
// calls for a single packet, because slapd multiplexes
// connections over a poll loop; ReadPacket blocks instead and
// hands a whole element here. See the package comment.
type Decoder struct {
	buf []byte
	pos int
}

// NewDecoder decodes the elements of b in order. For the
// contents of a constructed element, pass those contents.
func NewDecoder(b []byte) *Decoder {
	return &Decoder{buf: b}
}

// Done reports whether every element has been consumed.
func (d *Decoder) Done() bool {
	return d.pos >= len(d.buf)
}

// Rest returns the unconsumed bytes without advancing.
func (d *Decoder) Rest() []byte {
	return d.buf[d.pos:]
}

// Peek returns the next element's tag and contents without
// consuming it.
func (d *Decoder) Peek() (Tag, []byte, error) {
	t, content, _, err := element(d.buf[d.pos:])
	return t, content, err
}

// Next consumes the next element and returns its tag and
// contents.
func (d *Decoder) Next() (Tag, []byte, error) {
	t, content, n, err := element(d.buf[d.pos:])
	if err != nil {
		return 0, nil, err
	}
	d.pos += n
	return t, content, nil
}

// element parses one tag-length-contents triple at the front
// of b, returning the tag, the contents, and the total octets
// consumed. It follows ber_peek_element in liblber/decode.c:
// definite lengths only, and the contents must fit in what is
// left.
func element(b []byte) (Tag, []byte, int, error) {
	t, n, err := decodeTag(b)
	if err != nil {
		return 0, nil, 0, err
	}
	length, m, err := decodeLength(b[n:])
	if err != nil {
		return 0, nil, 0, err
	}
	n += m
	// "BER element should have enough data left".
	if length > uint64(len(b)-n) {
		return 0, nil, 0, ErrTruncated
	}
	end := n + int(length)
	return t, b[n:end], end, nil
}
