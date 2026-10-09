package gss

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// ErrAuth reports a credential that did not verify.
var ErrAuth = errors.New("gss: authentication failed")

// maxSkew is how far the client's clock may be out.
//
// Five minutes, which is Kerberos's own default and MIT's
// clockskew — not a number to choose freshly, because both ends
// have to agree and every deployment is already tuned to it.
const maxSkew = 5 * time.Minute

// Acceptor holds the service's long-term keys.
type Acceptor struct {
	kt *keytab.Keytab
}

// NewAcceptor reads a keytab.
//
// One file, as MIT's KRB5_KTNAME names, and no default path: a
// server that silently found /etc/krb5.keytab would advertise a
// mechanism whose identity nobody chose.
func NewAcceptor(path string) (*Acceptor, error) {
	kt, err := keytab.Load(path)
	if err != nil {
		return nil, fmt.Errorf("keytab %s: %w", path, err)
	}
	if len(kt.Entries) == 0 {
		return nil, fmt.Errorf(
			"keytab %s holds no key", path)
	}
	return &Acceptor{kt: kt}, nil
}

// Realm is the realm of the first key in the keytab.
//
// Used to decide whether a client's realm is the server's own,
// which is what settles whether the derived DN carries a realm
// RDN. The first entry rather than a configured value: a keytab
// for more than one realm is possible but not a case this has
// been able to compare against the C.
func (a *Acceptor) Realm() string {
	return a.kt.Entries[0].Principal.Realm
}

// Context is the state of one GSSAPI exchange, which spans
// several bind requests on one connection.
type Context struct {
	// step counts the client messages consumed so far.
	step int
	// key is the per-message key agreed by the AP exchange.
	key types.EncryptionKey
	// Principal is the authenticated client, set once the AP
	// exchange has succeeded. Authzid is what the client asked
	// to act as, usually empty.
	Principal string
	Authzid   string
}

// Step consumes one client token and produces the acceptor's
// reply. done reports that the exchange is finished and
// Principal is usable.
//
// has distinguishes an absent credentials field from an empty
// one, because the client's second message has no field at all —
// observed, not assumed, from upstream's own client.
func (a *Acceptor) Step(
	c *Context, token []byte, has bool,
) (reply []byte, done bool, err error) {
	switch c.step {
	case 0:
		reply, err = a.accept(c, token)
	case 1:
		reply, err = c.offer(has, token)
	case 2:
		err = c.finish(token)
		done = err == nil
	default:
		err = fmt.Errorf("%w: unexpected token", ErrToken)
	}
	if err != nil {
		return nil, false, err
	}
	c.step++
	return reply, done, nil
}

// accept verifies the AP-REQ and answers with an AP-REP.
func (a *Acceptor) accept(
	c *Context, token []byte,
) ([]byte, error) {
	id, inner, err := decodeInitial(token)
	if err != nil {
		return nil, err
	}
	if id != tokIDAPReq {
		return nil, fmt.Errorf(
			"%w: expected an AP-REQ", ErrToken)
	}
	var req messages.APReq
	if err := req.Unmarshal(inner); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrToken, err)
	}
	// No client address is checked: the ticket may carry
	// addresses, and a server behind a proxy or NAT sees one
	// that never matches. MIT's own default is addressless
	// tickets for this reason.
	ok, err := req.Verify(a.kt, maxSkew,
		types.HostAddress{}, nil)
	if err != nil || !ok {
		return nil, fmt.Errorf("%w: %v", ErrAuth, err)
	}
	c.key = replyKey(&req)
	c.Principal = principalOf(&req)
	rep, err := makeAPRep(&req)
	if err != nil {
		return nil, err
	}
	return encodeInitial(tokIDAPRep, rep), nil
}

// offer sends the security-layer offer.
func (c *Context) offer(
	has bool, token []byte,
) ([]byte, error) {
	if has && len(token) > 0 {
		return nil, fmt.Errorf(
			"%w: unexpected credential after the AP "+
				"exchange", ErrToken)
	}
	return offerToken(c.key, 0)
}

// finish reads the client's choice of security layer.
//
// Only no-layer is offered, so only no-layer may be chosen. A
// client asking for integrity or confidentiality has either
// ignored the offer or is talking to the wrong server, and
// pretending to agree would break every message after this one.
func (c *Context) finish(token []byte) error {
	layer, authzid, err := unwrapChoice(c.key, token)
	if err != nil {
		return err
	}
	if layer&(layerIntegrity|layerConf) != 0 {
		return fmt.Errorf(
			"%w: only the no-security-layer option is "+
				"offered", ErrToken)
	}
	if layer&layerNone == 0 {
		return fmt.Errorf(
			"%w: no security layer was chosen", ErrToken)
	}
	c.Authzid = authzid
	return nil
}

// principalOf renders the client's principal as
// user@REALM, which is the form Kerberos names are written in.
func principalOf(req *messages.APReq) string {
	enc := req.Ticket.DecryptedEncPart
	name := strings.Join(enc.CName.NameString, "/")
	return name + "@" + enc.CRealm
}
