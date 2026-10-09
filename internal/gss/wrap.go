package gss

import (
	"encoding/binary"
	"fmt"

	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Wrap token flags, RFC 4121 4.2.2.
//
// Only SentByAcceptor is set on what this sends: the payload is
// the security-layer negotiation, which must be integrity-
// protected but has nothing secret in it, and Sealed would
// encrypt it for no gain. No AcceptorSubkey either, because none
// is sent — see makeAPRep.
const (
	flagSentByAcceptor byte = 0x01
	flagSealed         byte = 0x02
)

// Security-layer bitmask values, RFC 4752 3.3.
const (
	layerNone      byte = 0x01
	layerIntegrity byte = 0x02
	layerConf      byte = 0x04
)

// maxBuffer is the largest token this acceptor will receive.
//
// Zero would be legal — RFC 4752 3.3 reads it as "no security
// layer wanted" — but a client reading zero alongside an offer
// of no-layer has nothing to size its own buffer by, and MIT
// echoes a plausible number back. 65536 is what slapd's Cyrus
// offered in the captured exchange.
const maxBuffer = 0x010000

// offerToken is the acceptor's security-layer offer: one octet
// of bitmask, three of maximum buffer size, integrity-protected.
func offerToken(
	key types.EncryptionKey, seq uint64,
) ([]byte, error) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], maxBuffer)
	buf[0] = layerNone
	payload := buf[:]
	return acceptorWrap(key, seq, payload)
}

// acceptorWrap builds an integrity-protected Wrap token.
//
// gokrb5 ships NewInitiatorWrapToken and no acceptor
// counterpart, which is the one asymmetry of using a client
// library on a server: the flags and the key usage both change
// direction, and getting either wrong fails as a bad checksum
// rather than as a type error.
func acceptorWrap(
	key types.EncryptionKey, seq uint64, payload []byte,
) ([]byte, error) {
	token := gssapi.WrapToken{
		Flags:     flagSentByAcceptor,
		EC:        0,
		RRC:       0,
		SndSeqNum: seq,
		Payload:   payload,
	}
	err := token.SetCheckSum(
		key, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		return nil, fmt.Errorf(
			"gss: signing the offer: %w", err)
	}
	// EC is the checksum's length on an unsealed token (RFC
	// 4121 4.2.6.2), and SetCheckSum does not set it, so the
	// marshalled token would claim a zero-length checksum.
	token.EC = uint16(len(token.CheckSum))
	return token.Marshal()
}

// unwrapChoice reads the client's answer to the offer.
//
// Returns the security layer it chose and the authorization
// identity it asked for, which is normally absent.
func unwrapChoice(
	key types.EncryptionKey, b []byte,
) (byte, string, error) {
	var token gssapi.WrapToken
	if err := token.Unmarshal(b, false); err != nil {
		return 0, "", fmt.Errorf(
			"%w: %v", ErrToken, err)
	}
	if token.Flags&flagSealed != 0 {
		return 0, "", fmt.Errorf(
			"%w: sealed tokens are not accepted",
			ErrToken)
	}
	ok, err := token.Verify(
		key, keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil || !ok {
		return 0, "", fmt.Errorf(
			"gss: the client's token did not verify")
	}
	return readChoice(token.Payload)
}

// readChoice splits the client's four-octet answer from the
// authorization identity that may follow it.
func readChoice(payload []byte) (byte, string, error) {
	if len(payload) < 4 {
		return 0, "", fmt.Errorf(
			"%w: short security-layer answer", ErrToken)
	}
	return payload[0], string(payload[4:]), nil
}
