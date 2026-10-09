package gss

import (
	"bytes"
	"errors"
	"fmt"
)

// ErrToken reports a malformed GSS-API token.
var ErrToken = errors.New("gss: malformed token")

// krb5OID is the Kerberos 5 mechanism OID, 1.2.840.113554.1.2.2,
// in its DER content octets. Spelled out rather than built from
// the dotted form because it is a constant of the protocol and
// appears in every initial token.
var krb5OID = []byte{
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
}

// Token identifiers from RFC 4121 4.1: the two octets that
// follow the mechanism OID inside an initial context token.
var (
	tokIDAPReq = [2]byte{0x01, 0x00}
	tokIDAPRep = [2]byte{0x02, 0x00}
)

// encodeInitial builds an RFC 2743 3.1 initial context token:
//
//	[APPLICATION 0] IMPLICIT SEQUENCE {
//	        thisMech  OBJECT IDENTIFIER,
//	        innerToken  ANY }
//
// The inner token is not an ASN.1 value at all — it is the
// two-octet identifier followed by raw Kerberos message bytes,
// which is why this is assembled rather than marshalled.
func encodeInitial(id [2]byte, inner []byte) []byte {
	oid := append([]byte{0x06, byte(len(krb5OID))},
		krb5OID...)
	body := append(oid, id[0], id[1])
	body = append(body, inner...)
	out := append([]byte{0x60}, derLength(len(body))...)
	return append(out, body...)
}

// decodeInitial reads an initial context token, returning the
// token identifier and the Kerberos message inside it.
func decodeInitial(b []byte) ([2]byte, []byte, error) {
	var id [2]byte
	if len(b) == 0 || b[0] != 0x60 {
		return id, nil, fmt.Errorf(
			"%w: not an initial context token", ErrToken)
	}
	rest, err := skipLength(b[1:])
	if err != nil {
		return id, nil, err
	}
	rest, err = expectOID(rest)
	if err != nil {
		return id, nil, err
	}
	if len(rest) < 2 {
		return id, nil, fmt.Errorf(
			"%w: no token identifier", ErrToken)
	}
	id[0], id[1] = rest[0], rest[1]
	return id, rest[2:], nil
}

// expectOID consumes the mechanism OID, refusing any other.
func expectOID(b []byte) ([]byte, error) {
	if len(b) < 2 || b[0] != 0x06 {
		return nil, fmt.Errorf(
			"%w: no mechanism OID", ErrToken)
	}
	n := int(b[1])
	if len(b) < 2+n {
		return nil, fmt.Errorf(
			"%w: truncated mechanism OID", ErrToken)
	}
	if !bytes.Equal(b[2:2+n], krb5OID) {
		return nil, fmt.Errorf(
			"%w: not the Kerberos 5 mechanism", ErrToken)
	}
	return b[2+n:], nil
}

// derLength encodes a DER definite length.
func derLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var digits []byte
	for v := n; v > 0; v >>= 8 {
		digits = append([]byte{byte(v)}, digits...)
	}
	return append([]byte{byte(0x80 | len(digits))}, digits...)
}

// skipLength steps over a DER length, returning the content.
//
// The length itself is not checked against what follows: the
// Kerberos decoder downstream reads its own structure, and a
// disagreement between the two shows up there rather than being
// diagnosed twice.
func skipLength(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf(
			"%w: truncated length", ErrToken)
	}
	if b[0] < 0x80 {
		return b[1:], nil
	}
	n := int(b[0] & 0x7f)
	if n == 0 || len(b) < 1+n {
		return nil, fmt.Errorf(
			"%w: bad length", ErrToken)
	}
	return b[1+n:], nil
}
