package store

import "time"

// Entry is one directory entry.
//
// The DN is stored three ways because each answers a different
// question, and recomputing any of them per query would be
// worse:
//
//	DN       the normalised form, the identity and the key
//	PrettyDN the form to hand back to a client
//	RevDN    the normalised RDNs reversed, for subtree search
//
// RevDN is the departure worth knowing about. back-mdb keeps a
// subtree count beside each entry's ID (back-mdb/dn2id.c:40)
// and walks parents; Postgres has no such structure, and the
// obvious translation — `dn LIKE '%,' || base` — cannot use an
// index, because the wildcard leads. Reversing the RDNs turns
// "is under" into a prefix test, which a btree index serves:
// cn=x,dc=example,dc=com is stored as dc=com,dc=example,cn=x,
// so everything under dc=example,dc=com shares the prefix
// dc=com,dc=example.
type Entry struct {
	ID       uint64 `gorm:"primaryKey"`
	DN       string `gorm:"uniqueIndex;not null"`
	PrettyDN string `gorm:"not null"`
	RevDN    string `gorm:"index;not null"`
	// ParentDN is the normalised parent, empty at a suffix
	// root. Indexed because one-level search is its only
	// question.
	ParentDN  string `gorm:"index;not null"`
	CreatedAt time.Time
	UpdatedAt time.Time

	Values []Value `gorm:"constraint:OnDelete:CASCADE"`
}

// Value is one attribute value.
//
// Flattened to a row per value rather than an array column:
// LDAP attributes are multi-valued and unordered, filters match
// per value, and a row per value is what lets the database do
// the matching.
type Value struct {
	ID      uint64 `gorm:"primaryKey"`
	EntryID uint64 `gorm:"index;not null"`
	// Type is the attribute's canonical name, lower-cased, so
	// a lookup never has to resolve an alias or an OID.
	Type string `gorm:"index;not null"`
	// Value is as the client sent it.
	Value string `gorm:"not null"`
	// Norm is the value under its equality matching rule,
	// which is what equality filters compare. Keeping both is
	// the same bargain as DN and PrettyDN.
	Norm string `gorm:"index;not null"`
}

// TableName keeps the table names explicit rather than letting
// GORM pluralise them.
func (Entry) TableName() string { return "entries" }

// TableName names the values table.
func (Value) TableName() string { return "attr_values" }
