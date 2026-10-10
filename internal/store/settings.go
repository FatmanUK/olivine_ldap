package store

import (
	"sync"
	"sync/atomic"

	"github.com/FatmanUK/olivine_ldap/internal/acl"
)

// settings is the configuration in force: everything cn=config
// can change while the server runs.
//
// It is immutable once published. Every operation reads the
// suffixes, the policy, the root identity and the limits, and
// those reads happen on a connection's goroutine while a
// modification of cn=config happens on another — so a field
// written in place would be a data race, and a lock taken per
// read would be on the path of every search. Instead a change
// builds a whole new settings and swaps the pointer: a reader
// holds one consistent generation for the length of its
// operation, and never blocks.
type settings struct {
	suffixes []string
	// access are the directives as olcAccess holds them, in
	// order, and policy is the same thing compiled. Both are
	// kept because the projection has to render back what was
	// set, and a compiled Policy cannot be unparsed.
	access []string
	// policy is nil for slapd's default of read on everything.
	policy       *acl.Policy
	rootDN       string
	rootPretty   string
	rootPassword string
	// limits are the administrative search limits. The zero
	// value means DefaultLimits.
	limits Limits
}

// conf returns the settings in force, never nil.
func (s *Store) conf() *settings {
	if c := s.current.Load(); c != nil {
		return c
	}
	return &settings{}
}

// clone copies the settings deeply enough to be modified.
//
// The slices are copied because a published generation may still
// be in use by an operation that is part-way through; appending
// to a shared backing array would change what it sees.
func (c *settings) clone() *settings {
	out := *c
	out.suffixes = append([]string(nil), c.suffixes...)
	out.access = append([]string(nil), c.access...)
	return &out
}

// mutate changes the settings under the write lock.
//
// The lock serialises read-modify-write, which the atomic swap
// alone does not: two concurrent modifications could each clone
// the same generation and one would be lost. Readers do not take
// it.
func (s *Store) mutate(fn func(*settings) error) error {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	next := s.conf().clone()
	if err := fn(next); err != nil {
		return err
	}
	s.current.Store(next)
	return nil
}

// configState is the mutable part of a Store, embedded so the
// Store declaration says what it holds rather than how.
type configState struct {
	current atomic.Pointer[settings]
	// configMu guards publishing: a change clones the current
	// generation and swaps it in, which two writers must not
	// do at once. Readers never take it.
	configMu sync.Mutex
	// writeMu serialises whole cn=config modifications, which
	// span a read of the stored rows, a validation and a
	// write. configMu cannot do that job as well: it is held
	// only for the swap, and holding it across the database
	// work would block it behind a query.
	writeMu sync.Mutex
}
