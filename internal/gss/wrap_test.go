package gss

import (
	"errors"
	"testing"

	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/types"
)

// testKey is a key of the type MIT negotiates by default.
func testKey() types.EncryptionKey {
	v := make([]byte, 32)
	for i := range v {
		v[i] = byte(i)
	}
	return types.EncryptionKey{
		KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
		KeyValue: v,
	}
}

// clientChoice is the token a client sends to answer the offer.
func clientChoice(
	t *testing.T, layer byte, authzid string,
) []byte {
	t.Helper()
	payload := append(
		[]byte{layer, 0x00, 0x00, 0x00}, authzid...)
	token, err := gssapi.NewInitiatorWrapToken(
		payload, testKey())
	if err != nil {
		t.Fatal(err)
	}
	b, err := token.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The offer is a four-octet payload: the bitmask, then the
// maximum buffer size big-endian. Only no-layer is offered.
func TestOfferToken(t *testing.T) {
	b, err := offerToken(testKey(), 0)
	if err != nil {
		t.Fatal(err)
	}
	var token gssapi.WrapToken
	if err := token.Unmarshal(b, true); err != nil {
		t.Fatal(err)
	}
	if token.Flags&flagSealed != 0 {
		t.Error("the offer is sealed; it should be " +
			"integrity-protected only")
	}
	// EC must be the checksum's length, or a client reading
	// the token finds the payload where the checksum is.
	if int(token.EC) != len(token.CheckSum) {
		t.Errorf("EC = %d, checksum is %d bytes",
			token.EC, len(token.CheckSum))
	}
	want := []byte{layerNone, 0x01, 0x00, 0x00}
	if string(token.Payload) != string(want) {
		t.Errorf("payload = %x, want %x",
			token.Payload, want)
	}
}

// The client's answer verifies and yields its choice.
func TestUnwrapChoice(t *testing.T) {
	layer, authzid, err := unwrapChoice(
		testKey(), clientChoice(t, layerNone, ""))
	if err != nil {
		t.Fatal(err)
	}
	if layer != layerNone || authzid != "" {
		t.Errorf("layer = %x, authzid = %q",
			layer, authzid)
	}
}

// A token signed with a different key is refused: that is the
// whole point of the exchange being integrity-protected.
func TestUnwrapChoiceRejectsABadChecksum(t *testing.T) {
	other := testKey()
	other.KeyValue[0] ^= 0xff
	_, _, err := unwrapChoice(
		other, clientChoice(t, layerNone, ""))
	if err == nil {
		t.Fatal("a forged token verified")
	}
}

// Only no-layer is offered, so only no-layer may be chosen.
func TestFinishRefusesASecurityLayer(t *testing.T) {
	for _, layer := range []byte{
		layerIntegrity, layerConf,
	} {
		c := &Context{key: testKey()}
		err := c.finish(clientChoice(t, layer, ""))
		if err == nil {
			t.Errorf("layer %x was accepted", layer)
			continue
		}
		if !errors.Is(err, ErrToken) {
			t.Errorf("layer %x: %v", layer, err)
		}
	}
}

// An authorization identity rides along after the four octets,
// and has to be read out so it can be refused by name.
func TestFinishReadsTheAuthzid(t *testing.T) {
	c := &Context{key: testKey()}
	err := c.finish(clientChoice(
		t, layerNone, "u:somebody"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Authzid != "u:somebody" {
		t.Errorf("authzid = %q", c.Authzid)
	}
}
