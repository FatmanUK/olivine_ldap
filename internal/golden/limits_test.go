//go:build golden

package golden

import (
	"os"
	"testing"

	"github.com/FatmanUK/olivine_ldap/internal/ldap"
	"github.com/FatmanUK/olivine_ldap/internal/store"
)

// limitsPort keeps this test off the other oracles' ports.
const limitsPort = oraclePort + 40

// adminSize is the administrative size limit both sides are given.
const adminSize = 3

// TestGoldenLimits compares search limits.
//
// The edges are where a guess goes wrong: exactly at the limit is
// success rather than sizeLimitExceeded, a request limit of 0 does
// not widen the administrator's, and rootdn is not subject to it
// at all. Each was established against the oracle.
func TestGoldenLimits(t *testing.T) {
	if os.Getenv("OLIVINE_TEST_DSN") == "" &&
		os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("needs a test database; " +
			"run `make golden-limits`")
	}
	oracle, err := StartOracleWith(limitsPort,
		"sizelimit 3")
	if err != nil {
		t.Fatalf("oracle: %v", err)
	}
	defer oracle.Stop()
	if err := oracle.Seed(); err != nil {
		t.Fatalf("seeding: %v\n%s", err, oracle.Logs())
	}

	st, err := OpenStore()
	if err != nil || st == nil {
		t.Skipf("no store: %v", err)
	}
	st.SetLimits(store.Limits{Size: adminSize})

	olivine, err := StartOlivineWith(NewBackend(st))
	if err != nil {
		t.Fatal(err)
	}
	defer olivine.Stop()

	for _, script := range limitScripts() {
		t.Run(script.Name, func(t *testing.T) {
			runPair(t, oracle, olivine, script)
		})
	}
}

// limitScripts are the searches used to observe the limits.
//
// The fixture holds nine entries beneath the base, so an unlimited
// subtree search overruns a limit of three.
func limitScripts() []Script {
	return []Script{
		sizeScript("size-no-request-limit", 0),
		sizeScript("size-request-below-admin", 1),
		sizeScript("size-request-above-admin", 10),
		exactlyAtLimitScript(),
		rootBypassScript(),
	}
}

// sizeScript searches the whole subtree with one request limit.
func sizeScript(name string, requestSize int32) Script {
	return Script{
		Name:        name,
		ResultsOnly: true,
		Requests: []Request{{
			Name: name, Op: ldap.ReqSearch,
			Body: limitedSearchBody(baseDN,
				presentFilter("objectClass"),
				requestSize),
		}},
	}
}

// exactlyAtLimitScript matches exactly the administrative limit.
//
// slapd answers success, not sizeLimitExceeded: code 4 means
// there were *more* than the limit, not that the limit was
// reached.
func exactlyAtLimitScript() Script {
	return Script{
		Name: "size-exactly-at-limit",
		Requests: []Request{{
			Name: "three devices", Op: ldap.ReqSearch,
			Body: limitedSearchBody(baseDN,
				substringFilter("cn", "dev", nil, ""),
				0),
		}},
	}
}

// rootBypassScript searches as the administrator, which is not
// subject to the limit at all.
func rootBypassScript() Script {
	return Script{
		Name: "size-root-bypasses",
		Requests: []Request{
			AdminBind(),
			{Name: "all nine", Op: ldap.ReqSearch,
				Body: limitedSearchBody(baseDN,
					presentFilter("objectClass"),
					0)},
		},
	}
}
