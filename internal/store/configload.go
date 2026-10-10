package store

import (
	"fmt"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"github.com/FatmanUK/olivine_ldap/internal/acl"
)

// The attribute names the configuration is keyed by, lower-cased
// because that is how a client's spelling arrives and the key is
// compared, not displayed.
const (
	keySizeLimit = "olcsizelimit"
	keyTimeLimit = "olctimelimit"
	keySuffix    = "olcsuffix"
	keyRootDN    = "olcrootdn"
	keyRootPW    = "olcrootpw"
	keyAccess    = "olcaccess"
)

// LoadConfig reads the configuration from the database and
// publishes it.
//
// Called on start and on every refresh, so a change made through
// one replica reaches the others. It replaces the whole
// configuration rather than merging: a setting whose rows have
// all been deleted has to go back to its default, and a merge
// would leave the old value in force.
func (s *Store) LoadConfig() error {
	var rows []Setting
	err := s.db.Order("entry, key, seq").
		Find(&rows).Error
	if err != nil {
		return fmt.Errorf("reading configuration: %w", err)
	}
	next, err := s.buildSettings(rows)
	if err != nil {
		return err
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	s.current.Store(next)
	return nil
}

// buildSettings turns rows into the settings to publish.
func (s *Store) buildSettings(
	rows []Setting,
) (*settings, error) {
	out := &settings{}
	byKey := group(rows)
	if err := s.loadIdentity(out, byKey); err != nil {
		return nil, err
	}
	if err := s.loadSuffixes(out, byKey); err != nil {
		return nil, err
	}
	if err := loadAccess(out, byKey[keyAccess]); err != nil {
		return nil, err
	}
	out.limits = Limits{
		Size: firstInt(byKey[keySizeLimit]),
		Time: firstInt(byKey[keyTimeLimit]),
	}
	return out, nil
}

// group collects the values of each attribute, in order.
func group(rows []Setting) map[string][]string {
	out := make(map[string][]string)
	for _, r := range rows {
		out[r.Key] = append(out[r.Key], r.Value)
	}
	return out
}

// loadIdentity reads the administrative identity.
func (s *Store) loadIdentity(
	out *settings, byKey map[string][]string,
) error {
	raw := first(byKey[keyRootDN])
	if raw == "" {
		return nil
	}
	norm, pretty, err := s.normalise(raw)
	if err != nil {
		return fmt.Errorf("olcRootDN: %w", err)
	}
	out.rootDN, out.rootPretty = norm, pretty
	out.rootPassword = first(byKey[keyRootPW])
	return nil
}

// loadSuffixes reads and normalises the naming contexts.
func (s *Store) loadSuffixes(
	out *settings, byKey map[string][]string,
) error {
	for _, raw := range byKey[keySuffix] {
		norm, _, err := s.normalise(raw)
		if err != nil {
			return fmt.Errorf("olcSuffix: %w", err)
		}
		out.suffixes = append(out.suffixes, norm)
	}
	return nil
}

// loadAccess compiles the access directives.
func loadAccess(out *settings, values []string) error {
	if len(values) == 0 {
		return nil
	}
	out.access = append([]string(nil), values...)
	policy, err := acl.Parse(accessText(values))
	if err != nil {
		return fmt.Errorf("olcAccess: %w", err)
	}
	out.policy = policy
	return nil
}

// accessText renders olcAccess values as a slapd.conf fragment.
//
// olcAccess omits the leading `access` keyword that slapd.conf
// requires — `to * by * read`, not `access to * by * read` — so
// the parser, which reads the file syntax, needs it put back.
func accessText(values []string) string {
	var b strings.Builder
	for _, v := range values {
		b.WriteString("access ")
		b.WriteString(stripIndex(v))
		b.WriteString("\n")
	}
	return b.String()
}

// stripIndex removes a leading {n} ordering prefix.
func stripIndex(v string) string {
	if _, ok := indexPrefix(v); !ok {
		return v
	}
	return v[strings.Index(v, "}")+1:]
}

// first returns the first value, empty when there are none.
func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// firstInt reads the first value as an int32, zero when absent
// or unreadable.
func firstInt(values []string) int32 {
	n, err := strconv.Atoi(first(values))
	if err != nil || n < 0 {
		return 0
	}
	return int32(n)
}

// saveSetting replaces every value of one attribute.
//
// Delete-then-insert rather than an update per row: the values
// are an ordered set whose length changes, and reconciling row
// by row would need the sequence numbers kept consistent for no
// gain. One transaction, so a reader never sees half of it.
func (s *Store) saveSetting(
	entry, key string, values []string,
) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		err := tx.Where("entry = ? AND key = ?",
			entry, key).Delete(&Setting{}).Error
		if err != nil {
			return err
		}
		rows := make([]Setting, 0, len(values))
		for i, v := range values {
			rows = append(rows, Setting{
				Entry: entry, Key: key,
				Seq: i, Value: v,
			})
		}
		if len(rows) == 0 {
			return nil
		}
		return tx.Create(&rows).Error
	})
}
