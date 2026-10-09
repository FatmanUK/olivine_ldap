package golden

import (
	"crypto/tls"
	"fmt"
	"io"
	"time"

	"github.com/FatmanUK/openldap_olivine/internal/ber"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// maxSASLSteps bounds a SASL exchange, so a server that never
// completes one fails the test rather than hanging it.
const maxSASLSteps = 8

// SASLOutcome is how a bind exchange ended.
//
// Steps is recorded but not compared: how many rounds a mechanism
// takes is the mechanism implementation's business, and the two
// legitimately differ. slapd's Cyrus-backed EXTERNAL answers
// saslBindInProgress once before completing; Olivine completes in
// one, which RFC 4422 3 allows — a client loops until the result
// is not saslBindInProgress, so either is interoperable.
//
// What must agree is where the exchange *ends*: the result code,
// and the identity it leaves behind.
type SASLOutcome struct {
	Result string
	Steps  int
}

// RunExternal binds SASL EXTERNAL to completion, then runs the
// rest of the script as the resulting identity.
//
// One connection throughout: the bound identity belongs to the
// connection, so a search on a fresh one would be anonymous.
func RunExternal(
	addr string, after Script,
) (SASLOutcome, *Transcript, error) {
	cert, err := loadClientCert()
	if err != nil {
		return SASLOutcome{}, nil, err
	}
	c, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return SASLOutcome{}, nil, err
	}
	defer c.Close()
	if err := c.SetDeadline(
		time.Now().Add(30 * time.Second)); err != nil {
		return SASLOutcome{}, nil, err
	}
	outcome, err := bindExternal(c)
	if err != nil {
		return outcome, nil, err
	}
	tr, err := runStepsFrom(
		c, after, int32(outcome.Steps)+1)
	return outcome, tr, err
}

// bindExternal drives the exchange until it stops being in
// progress.
func bindExternal(c io.ReadWriter) (SASLOutcome, error) {
	var out SASLOutcome
	for step := 1; step <= maxSASLSteps; step++ {
		// After the first round the credentials field is
		// present but empty: that is the client's half of
		// EXTERNAL, which carries an authorization identity
		// and normally leaves it blank.
		packet, err := externalBind(
			int32(step), step > 1)
		if err != nil {
			return out, err
		}
		if _, err := c.Write(packet); err != nil {
			return out, err
		}
		m, err := readOne(c)
		if err != nil {
			return out, err
		}
		code, _, err := parseResult(m.Body)
		if err != nil {
			return out, err
		}
		out.Steps = step
		out.Result = code.String()
		if code != ldap.SASLBindInProgress {
			return out, nil
		}
	}
	return out, fmt.Errorf(
		"SASL exchange did not finish in %d steps",
		maxSASLSteps)
}

// externalBind encodes one round of an EXTERNAL bind.
func externalBind(
	id int32, withCreds bool,
) ([]byte, error) {
	e := ber.NewEncoder()
	e.Begin(ldap.TagMessage)
	e.Int32(ldap.TagMsgID, id)
	e.Begin(ldap.ReqBind)
	e.Int32(ber.TagInteger, ldap.Version3)
	e.String(ldap.TagLDAPDN, "")
	e.Begin(ldap.AuthSASL)
	e.String(ber.TagOctetString, "EXTERNAL")
	if withCreds {
		e.String(ber.TagOctetString, "")
	}
	e.End()
	e.End()
	e.End()
	return e.Bytes()
}
