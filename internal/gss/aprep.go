package gss

import (
	"fmt"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// encAPRepPart is RFC 4120 5.5.2's EncAPRepPart.
//
// gokrb5 can read one but not write one — it is a client
// library, and only an acceptor ever sends an AP-REP — so the
// structure is declared here.
type encAPRepPart struct {
	CTime time.Time `asn1:"generalized,explicit,tag:0"`
	Cusec int       `asn1:"explicit,tag:1"`
	// Subkey and SeqNumber are optional and not sent; see
	// makeAPRep. They are declared so the structure is the
	// RFC's and not a subset of it.
	Subkey types.EncryptionKey `asn1:"explicit,optional,tag:2"`
	Seq    int64               `asn1:"explicit,optional,tag:3"`
}

// aprep is RFC 4120 5.5.2's AP-REP.
type aprep struct {
	PVNO    int                 `asn1:"explicit,tag:0"`
	MsgType int                 `asn1:"explicit,tag:1"`
	EncPart types.EncryptedData `asn1:"explicit,tag:2"`
}

// makeAPRep builds the mutual-authentication reply to an AP-REQ.
//
// The client proves it holds the service key by producing a
// ticket; the AP-REP proves the *server* holds it, by echoing
// the authenticator's timestamp encrypted under a key only the
// ticket's holder and the service know. The timestamp has to be
// the client's own, to the microsecond: a different one reads as
// a replay and MIT rejects it.
//
// No acceptor subkey is sent. RFC 4121 4.1 allows either, and
// omitting it means the per-message keys are the ones already
// agreed — the authenticator's subkey if the client offered one,
// otherwise the ticket session key — which is one fewer secret
// to generate and get wrong.
func makeAPRep(req *messages.APReq) ([]byte, error) {
	part := encAPRepPart{
		CTime: req.Authenticator.CTime,
		Cusec: req.Authenticator.Cusec,
	}
	plain, err := asn1.Marshal(part)
	if err != nil {
		return nil, err
	}
	plain = asn1tools.AddASNAppTag(
		plain, asnAppTag.EncAPRepPart)
	ed, err := crypto.GetEncryptedData(plain,
		replyKey(req), keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		return nil, fmt.Errorf(
			"gss: encrypting AP-REP: %w", err)
	}
	return marshalAPRep(ed)
}

// marshalAPRep wraps the encrypted part in an AP-REP.
func marshalAPRep(
	ed types.EncryptedData,
) ([]byte, error) {
	b, err := asn1.Marshal(aprep{
		PVNO:    iana.PVNO,
		MsgType: msgtype.KRB_AP_REP,
		EncPart: ed,
	})
	if err != nil {
		return nil, err
	}
	return asn1tools.AddASNAppTag(b, asnAppTag.APREP), nil
}

// replyKey is the key the AP-REP is encrypted under, and the one
// the per-message tokens use.
//
// RFC 4120 3.2.6: the subkey from the authenticator when there
// is one, the ticket's session key otherwise. MIT's client sends
// a subkey, so in practice this is always the subkey — but a
// client that sends none still has to work.
func replyKey(req *messages.APReq) types.EncryptionKey {
	if len(req.Authenticator.SubKey.KeyValue) > 0 {
		return req.Authenticator.SubKey
	}
	return req.Ticket.DecryptedEncPart.Key
}
