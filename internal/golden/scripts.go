package golden

import (
	"github.com/FatmanUK/openldap_olivine/internal/ber"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// Scripts are the comparisons that can run today.
//
// They deliberately cover only what both implementations can
// already answer: protocol-level behaviour on an empty
// database. The 113 entries under openldap/tests/scripts are
// the eventual corpus, but most of them need the operations
// (plan step 8), and a script that fails on both sides equally
// tells us nothing we did not already know.
func Scripts() []Script {
	return []Script{
		startTLSScript(),
		criticalControlScript(),
		anonymousSearchScript(),
	}
}

// startTLSScript checks StartTLS is refused rather than
// ignored. Olivine does not port starttls.c, but the oracle
// does, so this is the first place the two could differ in a
// way a client would notice.
func startTLSScript() Script {
	e := ber.NewEncoder()
	e.String(ldap.TagExopReqOID, ldap.OIDStartTLS)
	body, err := e.Bytes()
	if err != nil {
		panic(err)
	}
	return Script{
		Name: "starttls-over-tls",
		Requests: []Request{{
			Name: "starttls",
			Op:   ldap.ReqExtended,
			Body: body,
		}},
	}
}

// unknownOID is in the private-enterprise arc and belongs to
// nobody, so neither implementation can claim to support it.
//
// The Sync OIDs are deliberately not used here. slapd parses
// the Sync control before deciding whether it is supported, so
// a valueless one draws protocolError "Sync control value is
// absent" — which tests slapd's parser, not either server's
// handling of an unsupported critical control.
const unknownOID = "1.3.6.1.4.1.99999.1.1"

// criticalControlScript checks that a critical control neither
// side implements draws unavailableCriticalExtension, as RFC
// 4511 4.1.11 requires, rather than being ignored.
func criticalControlScript() Script {
	return Script{
		Name: "critical-unknown-control",
		Requests: []Request{{
			Name: "search+critical-unknown",
			Op:   ldap.ReqSearch,
			Body: baseSearchBody(),
			Controls: []ldap.Control{{
				OID:      unknownOID,
				Critical: true,
			}},
		}},
	}
}

// anonymousSearchScript searches without binding first.
func anonymousSearchScript() Script {
	return Script{
		Name: "anonymous-search",
		Pending: "search is plan step 8; Olivine answers " +
			"unwillingToPerform until then",
		Requests: []Request{{
			Name: "search",
			Op:   ldap.ReqSearch,
			Body: baseSearchBody(),
		}},
	}
}

// baseSearchBody is a base-scope search for objectClass.
func baseSearchBody() []byte {
	e := ber.NewEncoder()
	e.String(ldap.TagLDAPDN, "dc=example,dc=com")
	e.Enum(ber.TagEnumerated, int32(ldap.ScopeBase))
	e.Enum(ber.TagEnumerated, 0)
	e.Int32(ber.TagInteger, 0)
	e.Int32(ber.TagInteger, 0)
	e.Bool(ber.TagBoolean, false)
	// present filter (objectClass=*), context 7, primitive.
	e.String(0x87, "objectClass")
	e.Begin(ber.TagSequence)
	e.End()
	out, err := e.Bytes()
	if err != nil {
		panic(err)
	}
	return out
}
