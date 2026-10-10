package ldap

import (
	"testing"

	"github.com/FatmanUK/olivine_ldap/internal/ber"
)

// control encodes one Control for test input.
func control(
	e *ber.Encoder, oid string, crit bool, val []byte,
	hasVal bool,
) {
	e.Begin(ber.TagSequence)
	e.String(ber.TagOctetString, oid)
	if crit {
		e.Bool(ber.TagBoolean, true)
	}
	if hasVal {
		e.OctetString(ber.TagOctetString, val)
	}
	e.End()
}

// withControls wraps an operation plus a control list.
func withControls(
	build func(*ber.Encoder),
) ([]byte, error) {
	e := ber.NewEncoder()
	e.Begin(TagMessage)
	e.Int32(TagMsgID, 1)
	e.Raw(ReqUnbind, nil)
	e.Begin(TagControls)
	build(e)
	e.End()
	e.End()
	return e.Bytes()
}

func TestParseControls(t *testing.T) {
	packet, err := withControls(func(e *ber.Encoder) {
		control(e, "1.2.3", true, []byte("v"), true)
		control(e, "4.5.6", false, nil, false)
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseMessage(packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Controls) != 2 {
		t.Fatalf("controls = %d, want 2", len(m.Controls))
	}
	if m.Controls[0].OID != "1.2.3" {
		t.Errorf("oid = %q", m.Controls[0].OID)
	}
	if !m.Controls[0].Critical {
		t.Error("first control should be critical")
	}
	if string(m.Controls[0].Value) != "v" {
		t.Errorf("value = %q", m.Controls[0].Value)
	}
	if m.Controls[1].Critical {
		t.Error("second control should not be critical")
	}
	if m.Controls[1].HasValue {
		t.Error("second control should have no value")
	}
}

// criticality defaults to FALSE and may be omitted, so the
// element after the OID is either the boolean or the value.
// An absent value and an empty one are different things
// (RFC 4511 4.1.11), which is what HasValue records.
func TestControlValueWithoutCriticality(t *testing.T) {
	packet, err := withControls(func(e *ber.Encoder) {
		control(e, "1.2.3", false, []byte(""), true)
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseMessage(packet)
	if err != nil {
		t.Fatal(err)
	}
	c := m.Controls[0]
	if c.Critical {
		t.Error("should not be critical")
	}
	if !c.HasValue {
		t.Error("empty value is still a value")
	}
	if len(c.Value) != 0 {
		t.Errorf("value = %q, want empty", c.Value)
	}
}

func TestCriticalUnsupportedIsRefused(t *testing.T) {
	// No controls are implemented yet, so any critical one
	// must be refused with unavailableCriticalExtension
	// rather than ignored.
	cs := []Control{{OID: OIDSyncRequest, Critical: true}}
	oid, bad := IsCriticalUnsupported(cs)
	if !bad {
		t.Fatal("critical unknown control must be refused")
	}
	if oid != OIDSyncRequest {
		t.Errorf("oid = %q", oid)
	}
}

func TestNonCriticalUnsupportedIsIgnored(t *testing.T) {
	cs := []Control{{OID: OIDSyncRequest, Critical: false}}
	if _, bad := IsCriticalUnsupported(cs); bad {
		t.Fatal("non-critical control must be ignored")
	}
}
