package store

import (
	"strconv"
	"strings"

	"github.com/FatmanUK/olivine_ldap/internal/ber"
	"github.com/FatmanUK/olivine_ldap/internal/ldap"
)

// configEntry is one entry of the projection.
type configEntry struct {
	DN         string
	Attributes []ldap.AttributeChange
}

// configEntries renders the running configuration as entries.
//
// The attribute names are slapd's, so a client that already reads
// cn=config finds what it expects: olcSuffix, olcRootDN,
// olcSizeLimit and the rest. The values are whatever the
// environment set, read back from the running server rather than
// from the variables — so what is shown is what is in force, not
// what was asked for.
func (s *Store) configEntries() []configEntry {
	return []configEntry{
		s.globalEntry(), s.databaseEntry(),
	}
}

// globalEntry is cn=config itself.
func (s *Store) globalEntry() configEntry {
	limits := s.limitsOrDefault()
	return configEntry{
		DN: ConfigDN,
		Attributes: []ldap.AttributeChange{
			attr("objectClass", "olcGlobal"),
			attr("cn", "config"),
			// The message-size limits Olivine enforces,
			// which rise once a connection has bound —
			// slapd/slap.h:142-143.
			attr("olcSockbufMaxIncoming",
				itoa64(ber.MaxIncomingDefault)),
			attr("olcSockbufMaxIncomingAuth",
				itoa64(ber.MaxIncomingAuth)),
			attr("olcSizeLimit", itoa32(limits.Size)),
			attr("olcTimeLimit", itoa32(limits.Time)),
		},
	}
}

// databaseEntry is the single database.
//
// The root DN is shown; the root *password* is not, hashed or
// otherwise. slapd will hand back olcRootPW to a reader of
// cn=config, which is a disclosure this does not copy: a hash is
// still something to attack offline, and nothing needs to read it
// back.
func (s *Store) databaseEntry() configEntry {
	a := []ldap.AttributeChange{
		attr("objectClass", "olcDatabaseConfig"),
		attr("olcDatabase", "{1}postgres"),
	}
	if suffixes := s.Suffixes(); len(suffixes) > 0 {
		a = append(a, ldap.AttributeChange{
			Type: "olcSuffix", Values: suffixes,
		})
	}
	c := s.conf()
	if c.rootDN != "" {
		a = append(a, attr("olcRootDN", c.rootPretty))
	}
	if len(c.access) > 0 {
		a = append(a, ldap.AttributeChange{
			Type: "olcAccess", Values: indexed(c.access),
		})
	}
	return configEntry{DN: databaseDN, Attributes: a}
}

// indexed renders ordered values as slapd stores them.
//
// olcAccess is ordered and its order is its whole meaning — the
// first matching clause decides — so slapd prefixes each value
// with its position, {0}, {1}, and so on (bconfig.c:6190 reads
// the same prefix back when a value is inserted). Reproducing it
// means a client that round-trips the attribute keeps the order
// it read.
func indexed(values []string) []string {
	out := make([]string, 0, len(values))
	for i, v := range values {
		out = append(out, "{"+strconv.Itoa(i)+"}"+v)
	}
	return out
}

// projectConfig applies the requested attribute list.
//
// Every attribute here is operational in slapd's schema, so a
// plain search would return none of them. That is unhelpful for a
// tree whose whole content is configuration, and slapd returns
// them to a plain search too, so the usage split does not apply.
func projectConfig(
	e configEntry, req *ldap.SearchRequest,
) ldap.SearchEntry {
	out := ldap.SearchEntry{DN: e.DN}
	if onlyNoAttributes(req.Attributes) {
		return out
	}
	for _, a := range e.Attributes {
		if !configWanted(req.Attributes, a.Type) {
			continue
		}
		out.Attributes = append(out.Attributes, a)
	}
	return out
}

// configWanted reports whether one attribute was asked for.
func configWanted(requested []string, typ string) bool {
	if len(requested) == 0 {
		return true
	}
	for _, want := range requested {
		if want == ldap.AllUserAttributes ||
			want == ldap.AllOperationalAttributes {
			return true
		}
		if strings.EqualFold(want, typ) {
			return true
		}
	}
	return false
}

// attr builds a single-valued attribute.
func attr(typ, value string) ldap.AttributeChange {
	return ldap.AttributeChange{
		Type: typ, Values: []string{value},
	}
}

// itoa32 renders an int32.
func itoa32(n int32) string {
	return strconv.FormatInt(int64(n), 10)
}

// itoa64 renders an untyped size constant.
func itoa64(n uint64) string {
	return strconv.FormatUint(n, 10)
}
