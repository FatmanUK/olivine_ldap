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
		badSchemaAddScript(),
		substringScript(),
		orderingScript(),
		caseExactScript(),
		integerOrderingScript(),
		anonymousAddScript(),
		rootDSEScopeScript(),
		attributeUsageScript(),
		modDNScript(),
	}
}

// modDNScript renames a leaf and then moves it back.
//
// Bound as the administrator, because an anonymous update is
// refused before access control is even consulted. The rename is
// undone so the fixture is unchanged for whatever runs next, and
// so the script can run twice.
func modDNScript() Script {
	return Script{
		Name: "moddn-rename-leaf",
		Requests: append(
			renameLeafSteps(), renameSubtreeSteps()...),
	}
}

// renameLeafSteps renames a leaf and puts it back.
//
// The search between the two is the part that matters: slapd
// *replaces* the RDN attribute value, so cn becomes Robert. An
// implementation that moves only the DN leaves cn: Bob, and this
// search finds nothing.
func renameLeafSteps() []Request {
	people := "ou=people," + baseDN
	return []Request{
		AdminBind(),
		{Name: "rename Bob to Robert",
			Op: ldap.ReqModDN,
			Body: modDNBody("cn=Bob,"+people,
				"cn=Robert", true, "")},
		{Name: "search for Robert",
			Op: ldap.ReqSearch,
			Body: searchBody(baseDN,
				ldap.ScopeSubtree,
				equalityFilter("cn", "Robert"),
				[]string{"cn"})},
		{Name: "rename back",
			Op: ldap.ReqModDN,
			Body: modDNBody("cn=Robert,"+people,
				"cn=Bob", true, "")},
	}
}

// renameSubtreeSteps renames a non-leaf and puts it back.
//
// back-mdb renames a whole subtree, so this succeeds and every
// descendant moves with it. The search afterwards is the check:
// children left behind would be orphaned and the count would
// drop. An earlier version refused a non-leaf outright, on an
// assumption that upstream behaved like Delete.
func renameSubtreeSteps() []Request {
	humans := "ou=humans," + baseDN
	return []Request{
		{Name: "rename a non-leaf",
			Op: ldap.ReqModDN,
			Body: modDNBody("ou=people,"+baseDN,
				"ou=humans", true, "")},
		{Name: "children moved too",
			Op: ldap.ReqSearch,
			Body: searchBody(humans,
				ldap.ScopeSubtree,
				presentFilter("objectClass"),
				[]string{"cn"})},
		// Put it back, so the script is idempotent.
		{Name: "rename the subtree back",
			Op: ldap.ReqModDN,
			Body: modDNBody(humans,
				"ou=people", true, "")},
	}
}

// rootDSEScopeScript checks that the root DSE is base-scope only.
//
// slapd answers noSuchObject for a one-level or subtree search
// from an empty base, so the root DSE is not the top of a walkable
// tree: a client enumerating the directory has to read
// namingContexts and start again from there.
func rootDSEScopeScript() Script {
	return Script{
		Name: "rootdse-scope",
		Requests: []Request{
			{Name: "sub from root",
				Op: ldap.ReqSearch,
				Body: searchBody("",
					ldap.ScopeSubtree,
					presentFilter("objectClass"),
					nil)},
			{Name: "one from root",
				Op: ldap.ReqSearch,
				Body: searchBody("",
					ldap.ScopeOneLevel,
					presentFilter("objectClass"),
					nil)},
		},
	}
}

// attributeUsageScript checks the user/operational split.
//
// A plain search returns user attributes; "+" returns operational
// ones and *only* those, which is why slapd's "+" output carries
// no objectClass line (RFC 3673). Returning everything for both —
// which Olivine did until this script — agreed with slapd only by
// the accident of nothing operational being stored.
func attributeUsageScript() Script {
	alice := "cn=Alice,ou=people," + baseDN
	return Script{
		Name: "attribute-usage",
		Requests: []Request{
			{Name: "plain", Op: ldap.ReqSearch,
				Body: searchBody(alice,
					ldap.ScopeBase,
					presentFilter("objectClass"),
					nil)},
			{Name: "star", Op: ldap.ReqSearch,
				Body: searchBody(alice,
					ldap.ScopeBase,
					presentFilter("objectClass"),
					[]string{"*"})},
		},
	}
}

// anonymousAddScript adds a schema-valid entry without binding.
//
// slapd answers strongerAuthRequired (8), not insufficientAccess
// (50): an anonymous update is refused by a restriction on the
// connection before the ACLs are consulted at all, and a grant of
// `by * write` does not change it. Checking access first — which
// is what Olivine did before this comparison existed — gives 50.
func anonymousAddScript() Script {
	return Script{
		Name: "add-anonymous",
		Requests: []Request{{
			Name: "add",
			Op:   ldap.ReqAdd,
			Body: addBody("cn=New,"+baseDN, []attr{
				{"objectClass",
					[]string{"person"}},
				{"cn", []string{"New"}},
				{"sn", []string{"N"}},
			}),
		}},
	}
}

// integerOrderingScript orders under integerOrderingMatch.
//
// uidNumber declares it, so 9 < 10 < 100. A string comparison —
// which is what this did before internal/schema carried the
// matching rules — puts "10" and "100" below "9", and every one
// of these three filters would return the wrong set.
func integerOrderingScript() Script {
	return Script{
		Name: "filter-integer-ordering",
		Requests: []Request{
			{Name: "uidNumber>=10",
				Op: ldap.ReqSearch,
				Body: searchBody(baseDN,
					ldap.ScopeSubtree,
					avaFilter(ldap.FilterGE,
						"uidNumber", "10"),
					[]string{"uidNumber"})},
			{Name: "uidNumber<=10",
				Op: ldap.ReqSearch,
				Body: searchBody(baseDN,
					ldap.ScopeSubtree,
					avaFilter(ldap.FilterLE,
						"uidNumber", "10"),
					[]string{"uidNumber"})},
			{Name: "uidNumber=9", Op: ldap.ReqSearch,
				Body: searchBody(baseDN,
					ldap.ScopeSubtree,
					equalityFilter(
						"uidNumber", "9"),
					[]string{"uidNumber"})},
		},
	}
}

// substringScript exercises initial, any and final fragments.
//
// The fragments are normalised under the attribute's substrings
// rule with the use that says which fragment they are, because
// UTF8StringNormalize trims each differently. Getting that wrong
// drops asserted spaces, which is invisible until compared.
func substringScript() Script {
	return Script{
		Name: "filter-substrings",
		Requests: []Request{
			{Name: "cn=dev*", Op: ldap.ReqSearch,
				Body: searchBody(baseDN,
					ldap.ScopeSubtree,
					substringFilter("cn", "dev",
						nil, ""),
					[]string{"cn"})},
			{Name: "cn=*10", Op: ldap.ReqSearch,
				Body: searchBody(baseDN,
					ldap.ScopeSubtree,
					substringFilter("cn", "",
						nil, "10"),
					[]string{"cn"})},
			{Name: "cn=*ev1*", Op: ldap.ReqSearch,
				Body: searchBody(baseDN,
					ldap.ScopeSubtree,
					substringFilter("cn", "",
						[]string{"ev1"}, ""),
					[]string{"cn"})},
		},
	}
}

// orderingScript checks >= and <=.
//
// serialNumber's ordering rule is a string comparison, so "9" is
// greater than "10" here. That is the right answer and the
// counter-intuitive one, which is exactly why it is compared
// against the C rather than asserted from memory.
func orderingScript() Script {
	return Script{
		Name: "filter-ordering",
		Requests: []Request{
			{Name: "serialNumber>=10",
				Op: ldap.ReqSearch,
				Body: searchBody(baseDN,
					ldap.ScopeSubtree,
					avaFilter(ldap.FilterGE,
						"serialNumber", "10"),
					[]string{"serialNumber"})},
			{Name: "serialNumber<=10",
				Op: ldap.ReqSearch,
				Body: searchBody(baseDN,
					ldap.ScopeSubtree,
					avaFilter(ldap.FilterLE,
						"serialNumber", "10"),
					[]string{"serialNumber"})},
		},
	}
}

// caseExactScript checks that a case-sensitive filter on a
// caseIgnore attribute still matches, and that spacing is
// collapsed on both sides.
func caseExactScript() Script {
	return Script{
		Name: "filter-spacing",
		Requests: []Request{
			{Name: "cn=  Alice  ", Op: ldap.ReqSearch,
				Body: searchBody(baseDN,
					ldap.ScopeSubtree,
					equalityFilter("cn",
						"  Alice  "),
					[]string{"cn"})},
			{Name: "sn=aNdErSoN", Op: ldap.ReqSearch,
				Body: searchBody(baseDN,
					ldap.ScopeSubtree,
					equalityFilter("sn",
						"aNdErSoN"),
					[]string{"sn"})},
		},
	}
}

// badSchemaAddScript adds an entry whose objectClass is not
// defined. Both implementations must refuse it, and with the
// same code: slapd answers invalidSyntax, not
// objectClassViolation, because it validates the value against
// the objectClass syntax before considering the hierarchy.
func badSchemaAddScript() Script {
	return Script{
		Name: "add-undefined-objectclass",
		Requests: []Request{{
			Name: "add",
			Op:   ldap.ReqAdd,
			Body: addBody("cn=bad,"+baseDN,
				[]attr{{"objectClass",
					[]string{"nosuchclass"}}}),
		}},
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
