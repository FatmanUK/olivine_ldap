package golden

import (
	"github.com/FatmanUK/openldap_olivine/internal/ber"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// Scripts are the comparisons that need no data on either side.
//
// Protocol-level behaviour only, so they run without Postgres.
// Anything that depends on entries belongs in DataScripts: with
// no backend Olivine answers every operation
// unwillingToPerform, which would differ from the oracle for
// reasons that say nothing about either implementation.
//
// The 113 entries under openldap/tests/scripts are the eventual
// corpus.
func Scripts() []Script {
	return []Script{
		startTLSScript(),
		criticalControlScript(),
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

// DataScripts are the comparisons that need a seeded tree on
// both sides. They are separate from Scripts because they need
// Postgres, and the protocol-level ones do not.
func DataScripts() []Script {
	return []Script{
		searchScopeScript("search-base", ldap.ScopeBase),
		searchScopeScript("search-one", ldap.ScopeOneLevel),
		searchScopeScript("search-sub", ldap.ScopeSubtree),
		equalityFilterScript(),
		caseInsensitiveFilterScript(),
		missingBaseScript(),
		compareScript(),
	}
}

// searchScopeScript searches the seeded tree at one scope.
func searchScopeScript(
	name string, scope ldap.Scope,
) Script {
	return Script{
		Name: name,
		Requests: []Request{{
			Name: name,
			Op:   ldap.ReqSearch,
			Body: searchBody(baseDN, scope,
				presentFilter("objectClass"), nil),
		}},
	}
}

// equalityFilterScript checks an equality filter.
func equalityFilterScript() Script {
	return Script{
		Name: "filter-equality",
		Requests: []Request{{
			Name: "cn=Alice",
			Op:   ldap.ReqSearch,
			Body: searchBody(baseDN, ldap.ScopeSubtree,
				equalityFilter("cn", "Alice"), nil),
		}},
	}
}

// caseInsensitiveFilterScript checks that cn's inherited
// caseIgnoreMatch is honoured by both implementations.
func caseInsensitiveFilterScript() Script {
	return Script{
		Name: "filter-case-insensitive",
		Requests: []Request{{
			Name: "cn=aLiCe",
			Op:   ldap.ReqSearch,
			Body: searchBody(baseDN, ldap.ScopeSubtree,
				equalityFilter("cn", "aLiCe"), nil),
		}},
	}
}

// missingBaseScript searches a base that does not exist.
func missingBaseScript() Script {
	return Script{
		Name: "search-missing-base",
		Requests: []Request{{
			Name: "absent base",
			Op:   ldap.ReqSearch,
			Body: searchBody("dc=absent,dc=com",
				ldap.ScopeSubtree,
				presentFilter("objectClass"), nil),
		}},
	}
}

// compareScript checks compareTrue and compareFalse.
func compareScript() Script {
	return Script{
		Name: "compare",
		Requests: []Request{
			{Name: "true", Op: ldap.ReqCompare,
				Body: compareBody(
					"cn=Alice,ou=people,"+baseDN,
					"sn", "Anderson")},
			{Name: "false", Op: ldap.ReqCompare,
				Body: compareBody(
					"cn=Alice,ou=people,"+baseDN,
					"sn", "Nothere")},
		},
	}
}

// baseSearchBody is a base-scope search for objectClass, used
// by the scripts that only need a well-formed search to carry a
// control.
func baseSearchBody() []byte {
	return searchBody(baseDN, ldap.ScopeBase,
		presentFilter("objectClass"), nil)
}
