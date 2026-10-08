package ber

// Encoder builds a BER message.
//
// Errors are sticky: they are recorded and returned once from
// Bytes, so field-by-field calls need no error check. This
// replaces ber_printf's format language, which liblber's
// encode.c shows to be a pure dispatcher — every case calls a
// typed ber_put_* directly, and only 't' (tag override) and
// '!' (hook) carry any state. No on-the-wire behaviour hides
// in it, so nothing is lost by taking the tag as a parameter
// instead.
type Encoder struct {
	buf    []byte
	starts []int
	tags   []Tag
	err    error
}

// NewEncoder returns an empty Encoder.
func NewEncoder() *Encoder {
	return &Encoder{}
}

// Bytes returns the encoded message, or the first error.
func (e *Encoder) Bytes() ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	if len(e.starts) != 0 {
		return nil, ErrUnbalanced
	}
	return e.buf, nil
}

// Begin opens a constructed element. Every Begin needs an End.
//
// Contents accumulate in the buffer and the tag and length are
// written at End, once the length is known. The C solves the
// same problem by walking back over a seqorset list
// (ber_put_seqorset in encode.c) and shifting the contents;
// this keeps the shift but not the list.
func (e *Encoder) Begin(t Tag) {
	e.starts = append(e.starts, len(e.buf))
	e.tags = append(e.tags, t)
}

// End closes the innermost constructed element.
func (e *Encoder) End() {
	if len(e.starts) == 0 {
		e.fail(ErrUnbalanced)
		return
	}
	last := len(e.starts) - 1
	at, t := e.starts[last], e.tags[last]
	e.starts, e.tags = e.starts[:last], e.tags[:last]

	content := append([]byte(nil), e.buf[at:]...)
	e.buf = e.buf[:at]
	e.Raw(t, content)
}

// Raw writes one element with the given tag and contents.
func (e *Encoder) Raw(t Tag, content []byte) {
	e.writeTag(t)
	e.writeLength(uint64(len(content)))
	e.buf = append(e.buf, content...)
}

// OctetString writes contents as-is under t.
func (e *Encoder) OctetString(t Tag, s []byte) {
	e.Raw(t, s)
}

// String writes a Go string as an octet string.
func (e *Encoder) String(t Tag, s string) {
	e.Raw(t, []byte(s))
}

// Null writes a zero-length element.
func (e *Encoder) Null(t Tag) {
	e.Raw(t, nil)
}

// Bool writes a boolean. The C writes 0xff for true
// (ber_put_boolean in encode.c), not 0x01.
func (e *Encoder) Bool(t Tag, v bool) {
	if v {
		e.Raw(t, []byte{0xff})
		return
	}
	e.Raw(t, []byte{0x00})
}

// Int32 writes a minimal-length two's-complement integer,
// as ber_put_int_or_enum does.
func (e *Encoder) Int32(t Tag, v int32) {
	e.Raw(t, encodeInt(v))
}

// Enum writes an ENUMERATED, encoded as an integer.
func (e *Encoder) Enum(t Tag, v int32) {
	e.Int32(t, v)
}

// fail records the first error.
func (e *Encoder) fail(err error) {
	if e.err == nil {
		e.err = err
	}
}
