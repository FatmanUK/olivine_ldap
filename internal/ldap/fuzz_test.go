package ldap

import "testing"

// FuzzParseMessage feeds arbitrary packets to the envelope
// parser. Any error is acceptable; a panic is not. This is the
// first code a remote peer reaches after the BER layer, so it
// is the likeliest place for a crash to be reachable.
func FuzzParseMessage(f *testing.F) {
	f.Add(envelope(1, ReqUnbind, nil))
	f.Add(envelope(1, ReqBind, []byte{0x02, 0x01, 0x03}))
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	f.Add([]byte{0x30, 0x05, 0x02, 0x01, 0x01, 0x30, 0x82})

	f.Fuzz(func(t *testing.T, in []byte) {
		m, err := ParseMessage(in)
		if err != nil {
			return
		}
		// Anything that parses must be self-consistent.
		if m == nil {
			t.Fatal("nil message with nil error")
		}
		_ = IsRequest(m.Op)
		_, _ = IsCriticalUnsupported(m.Controls)
		for _, c := range m.Controls {
			if !c.HasValue && len(c.Value) != 0 {
				t.Fatalf("value %q without HasValue",
					c.Value)
			}
		}
	})
}
