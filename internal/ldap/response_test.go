package ldap

import (
	"testing"

	"github.com/FatmanUK/openldap_olivine/internal/ber"
)

func TestEncodeResultRoundTrips(t *testing.T) {
	packet, err := EncodeResult(42, ResBind, Result{
		Code:       InvalidCredentials,
		MatchedDN:  "",
		Diagnostic: "no",
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseMessage(packet)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != 42 {
		t.Errorf("id = %d, want 42", m.ID)
	}
	if m.Op != ResBind {
		t.Errorf("op = %#x, want %#x", m.Op, ResBind)
	}
	d := ber.NewDecoder(m.Body)
	_, codeBytes, err := d.Next()
	if err != nil {
		t.Fatal(err)
	}
	code, err := ber.Enum(codeBytes)
	if err != nil {
		t.Fatal(err)
	}
	if ResultCode(code) != InvalidCredentials {
		t.Errorf("code = %d, want %d",
			code, InvalidCredentials)
	}
}

func TestEncodeResultWithReferral(t *testing.T) {
	packet, err := EncodeResult(1, ResSearchResult, Result{
		Code:     Referral,
		Referral: []string{"ldap://a", "ldap://b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseMessage(packet)
	if err != nil {
		t.Fatal(err)
	}
	d := ber.NewDecoder(m.Body)
	for i := 0; i < 3; i++ {
		if _, _, err := d.Next(); err != nil {
			t.Fatal(err)
		}
	}
	tag, content, err := d.Next()
	if err != nil {
		t.Fatal(err)
	}
	if tag != TagReferral {
		t.Fatalf("tag = %#x, want %#x", tag, TagReferral)
	}
	rd := ber.NewDecoder(content)
	var got []string
	for !rd.Done() {
		_, u, err := rd.Next()
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, string(u))
	}
	if len(got) != 2 || got[0] != "ldap://a" {
		t.Fatalf("referrals = %q", got)
	}
}

// A notice of disconnection carries message id 0.
func TestEncodeNoticeUsesMsgIDZero(t *testing.T) {
	packet, err := EncodeNotice(Result{
		Code:       ProtocolError,
		Diagnostic: "unexpected data in PDU",
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseMessage(packet)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != 0 {
		t.Errorf("id = %d, want 0", m.ID)
	}
	if m.Op != ResExtended {
		t.Errorf("op = %#x, want %#x", m.Op, ResExtended)
	}
}

func TestCanBeUnsolicited(t *testing.T) {
	for _, c := range []ResultCode{
		ProtocolError, StrongerAuthRequired, Unavailable,
	} {
		if !CanBeUnsolicited(c) {
			t.Errorf("%v should be allowed", c)
		}
	}
	for _, c := range []ResultCode{
		Success, NoSuchObject, UnwillingToPerform,
	} {
		if CanBeUnsolicited(c) {
			t.Errorf("%v should not be allowed", c)
		}
	}
}

func TestResultCodeNames(t *testing.T) {
	cases := map[ResultCode]string{
		Success:            "success",
		UnwillingToPerform: "unwillingToPerform",
		ResultCode(0x7f):   "unknown",
		UnavailableCriticalExt: "unavailableCritical" +
			"Extension",
	}
	for c, want := range cases {
		if got := c.String(); got != want {
			t.Errorf("%#x = %q, want %q",
				int32(c), got, want)
		}
	}
}

func TestCompareCodesAreSuccess(t *testing.T) {
	// A compare that answers is not a compare that failed.
	for _, c := range []ResultCode{
		Success, CompareTrue, CompareFalse,
	} {
		if !c.IsSuccess() {
			t.Errorf("%v should count as success", c)
		}
	}
	if NoSuchObject.IsSuccess() {
		t.Error("noSuchObject is not success")
	}
}
