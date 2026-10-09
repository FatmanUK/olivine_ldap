package store

import (
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Setting is one configuration value.
//
// The configuration lives in Postgres rather than only in the
// environment, which is the departure from where this started.
// The reasoning is that 12-factor calls config what *varies
// between deploys*: a DSN and a certificate path do, and the
// suffixes, the limits and the access policy do not — they are
// identical across every replica, which makes them shared state,
// and the shared state store is already here and already
// replicated. Keeping them in the environment meant a change to
// any of them was a redeploy of every replica in lockstep.
//
// What cannot live here is whatever is needed before the database
// is reachable: the DSN itself, the TLS material, the listen
// address. Those stay environmental because there is nowhere else
// they could come from. See Config.
type Setting struct {
	ID uint64 `gorm:"primaryKey"`
	// Entry is the normalised DN of the configuration entry
	// the value belongs to, so the two entries the projection
	// shows keep their own attributes.
	Entry string `gorm:"not null;uniqueIndex:cfg,priority:1"`
	// Key is the attribute name, lower-cased.
	Key string `gorm:"not null;uniqueIndex:cfg,priority:2"`
	// Seq is the position of this value within its attribute.
	// It is the ordering olcAccess depends on; for a
	// single-valued setting it is always zero.
	Seq       int    `gorm:"not null;uniqueIndex:cfg,priority:3"`
	Value     string `gorm:"not null"`
	UpdatedAt time.Time
}

// TableName keeps the table name explicit.
func (Setting) TableName() string { return "config_settings" }

// Config is the configuration a server starts with.
//
// These are *defaults for first boot*, not the authority. A
// value already in the database wins, because that is where a
// change made over LDAP lands and a replica restarting must not
// undo it. An empty database takes these instead, so a directory
// stood up from nothing still comes up configured.
type Config struct {
	Suffixes []string
	// Access are directives in slapd.conf syntax, one per
	// element, without the leading `access` keyword — the form
	// olcAccess holds.
	Access           []string
	RootDN           string
	RootPasswordHash string
	Limits           Limits
}

// Bootstrap seeds the configuration from c and then loads
// whatever the database holds.
//
// Seeding and loading are one call because the order matters and
// getting it wrong is silent: loading first would publish an
// empty configuration on a fresh database, and seeding over an
// existing one would revert a change.
func (s *Store) Bootstrap(c Config) error {
	if err := s.seedConfig(c); err != nil {
		return err
	}
	return s.LoadConfig()
}

// seedConfig writes the defaults for whichever settings the
// database does not hold.
//
// Per attribute, not per row: a setting with values already
// present is left entirely alone, so deleting the last value of
// one does not invite the environment to put it back.
//
// Two replicas starting at once both find the same attributes
// absent and both insert. The unique index on (entry, key, seq)
// makes that harmless — the loser's rows conflict and are
// dropped — which is why the insert says DoNothing rather than
// checking and trusting the check.
func (s *Store) seedConfig(c Config) error {
	rows := settingRows(c)
	if len(rows) == 0 {
		return nil
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		var have []string
		err := tx.Model(&Setting{}).Distinct().
			Pluck("key", &have).Error
		if err != nil {
			return err
		}
		rows = withoutKeys(rows, have)
		if len(rows) == 0 {
			return nil
		}
		return tx.Clauses(clause.OnConflict{
			DoNothing: true,
		}).Create(&rows).Error
	})
}

// withoutKeys drops the rows whose attribute is already set.
func withoutKeys(rows []Setting, have []string) []Setting {
	seen := make(map[string]bool, len(have))
	for _, k := range have {
		seen[k] = true
	}
	out := make([]Setting, 0, len(rows))
	for _, r := range rows {
		if !seen[r.Key] {
			out = append(out, r)
		}
	}
	return out
}

// settingRows renders a Config as rows to insert.
func settingRows(c Config) []Setting {
	var out []Setting
	add := func(entry, key string, values ...string) {
		for i, v := range values {
			if v == "" {
				continue
			}
			out = append(out, Setting{
				Entry: entry, Key: key,
				Seq: i, Value: v,
			})
		}
	}
	l := c.Limits
	if l == (Limits{}) {
		l = DefaultLimits
	}
	add(ConfigDN, keySizeLimit, itoa32(l.Size))
	add(ConfigDN, keyTimeLimit, itoa32(l.Time))
	add(databaseDN, keySuffix, c.Suffixes...)
	add(databaseDN, keyRootDN, c.RootDN)
	add(databaseDN, keyRootPW, c.RootPasswordHash)
	add(databaseDN, keyAccess, c.Access...)
	return out
}
