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
// Configuration proper is plan step 10; until then a caller
// declares the suffixes directly.
func (s *Store) AddSuffix(rawDN string) error {
	norm, _, err := s.normalise(rawDN)
	if err != nil {
		return err
	}
	s.suffixes = append(s.suffixes, norm)
	return nil
}

// isSuffix reports whether norm is exactly a suffix.
func (s *Store) isSuffix(norm string) bool {
	for _, suf := range s.suffixes {
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
	for _, suf := range s.suffixes {
		if norm == suf ||
			strings.HasSuffix(norm, ","+suf) {
			return true
		}
	}
	return false
}

// Suffixes returns the declared naming contexts.
func (s *Store) Suffixes() []string {
	out := make([]string, len(s.suffixes))
	copy(out, s.suffixes)
	return out
}
