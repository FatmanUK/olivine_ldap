package store

import (
	"errors"
	"strings"
)

// ErrOutOfScope reports a DN no configured suffix holds.
var ErrOutOfScope = errors.New(
	"store: DN is outside every suffix")

// AddSuffix declares a naming context this store holds.
//
// slapd takes these from `suffix "dc=example,dc=com"` in
// slapd.conf, and they matter for two reasons:
//
// An entry whose DN *is* a suffix has no parent in the database
// and must still be addable. dc=example,dc=com is the usual
// example: nothing holds dc=com, so requiring a parent for every
// multi-RDN DN makes the tree impossible to start.
//
// A DN under no suffix does not belong here at all.
//
// A caller may declare one directly, which is what the tests do.
// That is an in-memory override and does not persist: a write to
// cn=config republishes the whole configuration from the
// database, and a suffix declared only here would be lost at that
// point. Bootstrap is how a server declares them for real.
func (s *Store) AddSuffix(rawDN string) error {
	norm, _, err := s.normalise(rawDN)
	if err != nil {
		return err
	}
	return s.mutate(func(c *settings) error {
		c.suffixes = append(c.suffixes, norm)
		return nil
	})
}

// isSuffix reports whether norm is exactly a suffix.
func (s *Store) isSuffix(norm string) bool {
	for _, suf := range s.conf().suffixes {
		if norm == suf {
			return true
		}
	}
	return false
}

// inScope reports whether norm is at or under some suffix.
//
// The separator is required so that dc=examplecorp,dc=com is
// not treated as living under dc=example,dc=com.
func (s *Store) inScope(norm string) bool {
	for _, suf := range s.conf().suffixes {
		if norm == suf ||
			strings.HasSuffix(norm, ","+suf) {
			return true
		}
	}
	return false
}

// Suffixes returns the declared naming contexts.
func (s *Store) Suffixes() []string {
	have := s.conf().suffixes
	out := make([]string, len(have))
	copy(out, have)
	return out
}
