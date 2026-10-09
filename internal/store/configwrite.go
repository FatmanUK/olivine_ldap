package store

import (
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// configTable is every configuration value, by entry and then by
// attribute, each attribute's values in order.
type configTable map[string]map[string][]string

// knownConfigEntry reports whether a DN is one of the two
// entries the configuration consists of.
//
// Everything else under cn=config is noSuchObject rather than
// creatable: slapd can hold several databases and numbers them,
// and Olivine holds exactly one, so there is no entry a client
// could usefully add.
func knownConfigEntry(norm string) bool {
	return norm == ConfigDN || norm == databaseDN
}

// modifyConfig changes the running configuration.
//
// The write is validated in full before any of it is stored: the
// proposed table is compiled into the settings it would produce,
// and only a configuration that compiles is persisted. Otherwise
// a directive that parses alone but not in company — or a DN the
// schema cannot normalise — would be written and then refuse to
// load, which a restart would turn into a server that will not
// start.
func (s *Store) modifyConfig(
	req *ldap.ModifyRequest, who Identity,
) ldap.Result {
	base, ok := s.configBase(req.Object)
	if !ok || !knownConfigEntry(base) {
		return ldap.Result{Code: ldap.NoSuchObject}
	}
	// Hidden from everyone but the administrator, exactly as
	// the read side is: a caller who cannot see cn=config
	// learns nothing from trying to write it either.
	if !s.isRoot(who) {
		return ldap.Result{Code: ldap.NoSuchObject}
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	table, err := s.readConfigTable()
	if err != nil {
		return ldap.Result{
			Code: ldap.Other, Diagnostic: err.Error(),
		}
	}
	touched, res := s.applyConfigMods(base, table, req)
	if res.Code != ldap.Success {
		return res
	}
	return s.commitConfig(base, table, touched)
}

// commitConfig validates the proposed table, stores it and
// publishes it.
func (s *Store) commitConfig(
	base string, table configTable, touched []string,
) ldap.Result {
	next, err := s.buildSettings(tableRows(table))
	if err != nil {
		return configResult(err)
	}
	if res, ok := refuseLockout(next); !ok {
		return res
	}
	for _, key := range touched {
		err := s.saveSetting(
			base, key, table[base][key])
		if err != nil {
			return ldap.Result{
				Code:       ldap.Other,
				Diagnostic: err.Error(),
			}
		}
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	s.current.Store(next)
	return ldap.Result{Code: ldap.Success}
}

// refuseLockout stops a change that would leave nobody able to
// make the next one.
//
// cn=config answers to the administrator and to nobody else, and
// the administrator is olcRootDN — so deleting it would make the
// configuration unreachable over LDAP for good, since the
// environment's defaults apply only to a setting that is absent
// at boot and this one would not be. slapd permits the
// equivalent, because its cn=config has a rootdn of its own to
// fall back on; Olivine has one identity and refuses to drop it.
func refuseLockout(next *settings) (ldap.Result, bool) {
	if next.rootDN != "" {
		return ldap.Result{}, true
	}
	return ldap.Result{
		Code: ldap.UnwillingToPerform,
		Diagnostic: "olcRootDN cannot be removed: " +
			"nothing else may write cn=config",
	}, false
}

// applyConfigMods applies every modification to the table,
// returning the attributes it changed.
func (s *Store) applyConfigMods(
	base string, table configTable,
	req *ldap.ModifyRequest,
) ([]string, ldap.Result) {
	seen := make(map[string]bool)
	for _, m := range req.Modifications {
		a, err := findConfigAttr(base, m.Attribute.Type)
		if err != nil {
			return nil, configResult(err)
		}
		next, res := s.applyOne(
			a, table[base][a.key], m)
		if res.Code != ldap.Success {
			return nil, res
		}
		if table[base] == nil {
			table[base] = map[string][]string{}
		}
		table[base][a.key] = next
		seen[a.key] = true
	}
	return sortedKeys(seen), ldap.Result{Code: ldap.Success}
}

// applyOne applies one modification to one attribute's values.
func (s *Store) applyOne(
	a configAttr, cur []string, m ldap.Modification,
) ([]string, ldap.Result) {
	values, res := s.checkValues(a, m.Attribute.Values)
	if res.Code != ldap.Success {
		return nil, res
	}
	switch m.Op {
	case ldap.ModifyAdd:
		return addConfig(a, cur, values, m)
	case ldap.ModifyDelete:
		return deleteConfig(a, cur, values)
	case ldap.ModifyReplace:
		if res, ok := allowMulti(a, values); !ok {
			return nil, res
		}
		return values, ldap.Result{Code: ldap.Success}
	}
	return nil, ldap.Result{
		Code:       ldap.ProtocolError,
		Diagnostic: "bad modification type",
	}
}

// checkValues validates every value of a modification.
func (s *Store) checkValues(
	a configAttr, raw []string,
) ([]string, ldap.Result) {
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		checked, err := a.check(s, v)
		if err != nil {
			return nil, configResult(err)
		}
		out = append(out, checked)
	}
	return out, ldap.Result{Code: ldap.Success}
}

// addConfig adds values, placing them by a {n} prefix where the
// attribute is ordered.
func addConfig(
	a configAttr, cur, values []string,
	m ldap.Modification,
) ([]string, ldap.Result) {
	if res, ok := allowMulti(a, values); !ok {
		return nil, res
	}
	next := append([]string(nil), cur...)
	if !a.multi && len(next) > 0 {
		return nil, multipleValues(a)
	}
	at := insertPoint(a, m.Attribute.Values, len(next))
	rest := append([]string(nil), next[at:]...)
	next = append(next[:at], values...)
	return append(next, rest...),
		ldap.Result{Code: ldap.Success}
}

// insertPoint reads the {n} prefix of the first added value,
// which is how slapd places a value within an ordered attribute
// (bconfig.c:6190). Without one, the values go at the end.
func insertPoint(
	a configAttr, raw []string, end int,
) int {
	if !a.ordered || len(raw) == 0 {
		return end
	}
	n, ok := indexPrefix(raw[0])
	if !ok || n > end {
		return end
	}
	return n
}

// deleteConfig removes values, or all of them when none is
// named.
func deleteConfig(
	a configAttr, cur, values []string,
) ([]string, ldap.Result) {
	if len(values) == 0 {
		return nil, ldap.Result{Code: ldap.Success}
	}
	next := append([]string(nil), cur...)
	for _, v := range values {
		at := indexOf(next, v)
		if at < 0 {
			return nil, ldap.Result{
				Code:       ldap.NoSuchAttribute,
				Diagnostic: a.name,
			}
		}
		next = append(next[:at], next[at+1:]...)
	}
	return next, ldap.Result{Code: ldap.Success}
}

// allowMulti refuses more than one value for a single-valued
// attribute.
//
// constraintViolation with "multiple values provided" is what
// modify.c:645 answers, which is a different code from the one
// an entry's schema check gives for the same mistake.
func allowMulti(
	a configAttr, values []string,
) (ldap.Result, bool) {
	if a.multi || len(values) <= 1 {
		return ldap.Result{}, true
	}
	return multipleValues(a), false
}

// multipleValues is slapd's diagnostic, verbatim.
func multipleValues(a configAttr) ldap.Result {
	return ldap.Result{
		Code: ldap.ConstraintViolation,
		Diagnostic: a.name +
			": multiple values provided",
	}
}

// configResult maps a configuration failure to a result code.
//
// An attribute the table does not carry is unwillingToPerform,
// which is what config_modify_internal starts rc at
// (bconfig.c:6044) and answers for anything it cannot place.
func configResult(err error) ldap.Result {
	if errors.Is(err, errNotWritable) {
		return ldap.Result{
			Code:       ldap.UnwillingToPerform,
			Diagnostic: err.Error(),
		}
	}
	return resultFor(err)
}

// indexOf finds a value, ignoring any {n} prefix the client
// included.
func indexOf(values []string, want string) int {
	want = stripIndex(want)
	for i, v := range values {
		if v == want {
			return i
		}
	}
	return -1
}

// sortedKeys returns the keys of a set, in order, so a write
// touching two attributes stores them predictably.
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// readConfigTable reads every configuration value.
func (s *Store) readConfigTable() (configTable, error) {
	var rows []Setting
	err := s.db.Order("entry, key, seq").
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make(configTable)
	for _, r := range rows {
		if out[r.Entry] == nil {
			out[r.Entry] = map[string][]string{}
		}
		out[r.Entry][r.Key] = append(
			out[r.Entry][r.Key], r.Value)
	}
	return out, nil
}

// tableRows flattens a table back into rows, which is what
// buildSettings reads — so a proposed configuration is compiled
// by exactly the code that compiles a stored one.
func tableRows(table configTable) []Setting {
	var out []Setting
	for _, entry := range sortedTableKeys(table) {
		keys := table[entry]
		for _, key := range sortedStringKeys(keys) {
			for i, v := range keys[key] {
				out = append(out, Setting{
					Entry: entry, Key: key,
					Seq: i, Value: v,
				})
			}
		}
	}
	return out
}

// sortedTableKeys orders the entries of a table.
func sortedTableKeys(t configTable) []string {
	out := make([]string, 0, len(t))
	for k := range t {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedStringKeys orders the attributes of one entry.
func sortedStringKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// indexPrefix reads a leading {n}, reporting whether there was
// one.
func indexPrefix(v string) (int, bool) {
	if !strings.HasPrefix(v, "{") {
		return 0, false
	}
	i := strings.Index(v, "}")
	if i < 2 {
		return 0, false
	}
	n, err := strconv.Atoi(v[1:i])
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
