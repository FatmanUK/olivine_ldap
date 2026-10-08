package ber

import (
	"errors"
	"testing"
)

// wantErr asserts that got matches want, and reports whether
// the caller should stop. Extracted because the assertion at
// four levels of nesting does not fit 70 columns.
func wantErr(t *testing.T, got, want error) bool {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("err = %v, want %v", got, want)
	}
	return got != nil
}
