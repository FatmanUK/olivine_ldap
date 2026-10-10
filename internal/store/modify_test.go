package store

import (
	"errors"
	"sort"
	"testing"

	"github.com/FatmanUK/olivine_ldap/internal/ldap"
)

// valuesOf lists one attribute's values, sorted.
func valuesOf(e *Entry, typ string) []string {
	var out []string
	for _, v := range e.Values {
		if v.Type == typ {
			out = append(out, v.Value)
		}
	}
	sort.Strings(out)
	return out
}

const alice = "cn=Alice,ou=people,dc=example,dc=com"

func TestModifyAdd(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	err := s.Modify(alice, []Mod{{
		Op: ModAdd,
		Attribute: Attribute{"description",
			[]string{"first", "second"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.Get(alice)
	if err != nil {
		t.Fatal(err)
	}
	got := valuesOf(e, "description")
	if len(got) != 2 || got[0] != "first" {
		t.Fatalf("description = %v", got)
	}
}

// RFC 4511 4.6: adding a value already present is
// attributeOrValueExists, not a silent no-op.
func TestModifyAddDuplicateValue(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	err := s.Modify(alice, []Mod{{
		Op:        ModAdd,
		Attribute: Attribute{"cn", []string{"Alice"}},
	}})
	if !errors.Is(err, ErrValueExists) {
		t.Fatalf("err = %v, want ErrValueExists", err)
	}
}

// A duplicate differing only in case is still a duplicate under
// caseIgnoreMatch, which cn inherits from name.
func TestModifyAddCaseVariantIsDuplicate(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	err := s.Modify(alice, []Mod{{
		Op:        ModAdd,
		Attribute: Attribute{"cn", []string{"ALICE"}},
	}})
	if !errors.Is(err, ErrValueExists) {
		t.Fatalf("err = %v, want ErrValueExists", err)
	}
}

func TestModifyReplace(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	err := s.Modify(alice, []Mod{{
		Op:        ModReplace,
		Attribute: Attribute{"sn", []string{"Ashford"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.Get(alice)
	if err != nil {
		t.Fatal(err)
	}
	got := valuesOf(e, "sn")
	if len(got) != 1 || got[0] != "Ashford" {
		t.Fatalf("sn = %v", got)
	}
}

// RFC 4511 4.6: a replace with no values deletes the attribute.
//
// description, not sn: person MUST have sn, so removing it is an
// objectClassViolation and would test the schema check instead.
func TestModifyReplaceNoValuesDeletes(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	addDescription(t, s)
	err := s.Modify(alice, []Mod{{
		Op:        ModReplace,
		Attribute: Attribute{Type: "description"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.Get(alice)
	if err != nil {
		t.Fatal(err)
	}
	if got := valuesOf(e, "description"); len(got) != 0 {
		t.Fatalf("description = %v, want gone", got)
	}
}

// addDescription gives Alice an optional attribute to remove.
func addDescription(t *testing.T, s *Store) {
	t.Helper()
	err := s.Modify(alice, []Mod{{
		Op: ModAdd,
		Attribute: Attribute{"description",
			[]string{"removable"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
}

// Removing a MUST attribute is an objectClassViolation, which is
// what slapd answers: "object class 'person' requires attribute
// 'sn'".
func TestModifyCannotRemoveRequiredAttribute(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	err := s.Modify(alice, []Mod{{
		Op:        ModDelete,
		Attribute: Attribute{Type: "sn"},
	}})
	if err == nil {
		t.Fatal("removing sn from a person should fail")
	}
	res := resultFor(err)
	if res.Code != ldap.ObjectClassViolation {
		t.Errorf("code = %v, want objectClassViolation",
			res.Code)
	}
}

// RFC 4511 4.6: a delete with no values removes the whole
// attribute, which is quite different from a no-op.
func TestModifyDeleteNoValuesRemovesAttribute(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	addDescription(t, s)
	err := s.Modify(alice, []Mod{{
		Op:        ModDelete,
		Attribute: Attribute{Type: "description"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.Get(alice)
	if err != nil {
		t.Fatal(err)
	}
	if got := valuesOf(e, "description"); len(got) != 0 {
		t.Fatalf("description = %v, want gone", got)
	}
}

func TestModifyDeleteMissingValue(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	err := s.Modify(alice, []Mod{{
		Op:        ModDelete,
		Attribute: Attribute{"sn", []string{"Nothere"}},
	}})
	if !errors.Is(err, ErrNoSuchValue) {
		t.Fatalf("err = %v, want ErrNoSuchValue", err)
	}
}

// RFC 4511 4.6 requires the whole modification list to apply or
// none of it. The second mod here fails, so the first must not
// survive.
func TestModifyIsAtomic(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	err := s.Modify(alice, []Mod{
		{Op: ModAdd, Attribute: Attribute{"description",
			[]string{"added"}}},
		{Op: ModDelete, Attribute: Attribute{"sn",
			[]string{"Nothere"}}},
	})
	if err == nil {
		t.Fatal("expected the list to fail")
	}
	e, err := s.Get(alice)
	if err != nil {
		t.Fatal(err)
	}
	if got := valuesOf(e, "description"); len(got) != 0 {
		t.Fatalf("description = %v; the failed list "+
			"partially applied", got)
	}
}

// RFC 4511 4.8: delete applies to a leaf only.
func TestDeleteRefusesNonLeaf(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	err := s.Delete("ou=people,dc=example,dc=com")
	if !errors.Is(err, ErrNotLeaf) {
		t.Fatalf("err = %v, want ErrNotLeaf", err)
	}
}

func TestDeleteLeaf(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	if err := s.Delete(alice); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(alice); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	// And its values must be gone, not orphaned.
	got, err := s.Search("ou=people,dc=example,dc=com",
		ldap.ScopeOneLevel)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("%d siblings remain, want 1", len(got))
	}
}
