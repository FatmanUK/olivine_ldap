package schema

import (
	"fmt"
	"strings"
)

// Registry holds the schema in force.
//
// Lookup is by OID or by any of a definition's names, and names
// are matched case-insensitively: RFC 4512 2.5 makes
// descriptors case-insensitive, and slapd folds them.
type Registry struct {
	attrsByOID  map[string]*AttributeType
	attrsByName map[string]*AttributeType
	ocsByOID    map[string]*ObjectClass
	ocsByName   map[string]*ObjectClass
	macros      macros
	rulesByOID  map[string]*MatchingRule
	rulesByName map[string]*MatchingRule

	// Skipped records definitions that were recognised as
	// definitions but not registered, with the reason.
	//
	// slapd silently ignores an unknown directive in a schema
	// file, so refusing one would reject files slapd accepts
	// — including upstream's own dsee.schema. Recording them
	// keeps the silence from being total.
	Skipped []Skip
}

// Skip is one definition that was not registered.
type Skip struct {
	Keyword string
	Reason  string
	Snippet string
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	r := &Registry{
		attrsByOID:  map[string]*AttributeType{},
		attrsByName: map[string]*AttributeType{},
		ocsByOID:    map[string]*ObjectClass{},
		ocsByName:   map[string]*ObjectClass{},
		macros:      macros{},
		rulesByOID:  map[string]*MatchingRule{},
		rulesByName: map[string]*MatchingRule{},
	}
	r.registerRules()
	return r
}

// AddAttributeType registers at.
func (r *Registry) AddAttributeType(
	at *AttributeType,
) error {
	if _, dup := r.attrsByOID[at.OID]; dup {
		return fmt.Errorf("%w: attribute %s",
			ErrDup, at.OID)
	}
	r.attrsByOID[at.OID] = at
	for _, n := range at.Names {
		key := strings.ToLower(n)
		if _, dup := r.attrsByName[key]; dup {
			return fmt.Errorf("%w: attribute name %s",
				ErrDup, n)
		}
		r.attrsByName[key] = at
	}
	return nil
}

// AddObjectClass registers oc.
func (r *Registry) AddObjectClass(
	oc *ObjectClass,
) error {
	if _, dup := r.ocsByOID[oc.OID]; dup {
		return fmt.Errorf("%w: objectClass %s",
			ErrDup, oc.OID)
	}
	r.ocsByOID[oc.OID] = oc
	for _, n := range oc.Names {
		key := strings.ToLower(n)
		if _, dup := r.ocsByName[key]; dup {
			return fmt.Errorf("%w: objectClass name %s",
				ErrDup, n)
		}
		r.ocsByName[key] = oc
	}
	return nil
}

// AttributeType finds an attribute type by OID or name.
func (r *Registry) AttributeType(
	key string,
) (*AttributeType, bool) {
	if at, ok := r.attrsByOID[key]; ok {
		return at, true
	}
	at, ok := r.attrsByName[strings.ToLower(key)]
	return at, ok
}

// ObjectClass finds an object class by OID or name.
func (r *Registry) ObjectClass(
	key string,
) (*ObjectClass, bool) {
	if oc, ok := r.ocsByOID[key]; ok {
		return oc, true
	}
	oc, ok := r.ocsByName[strings.ToLower(key)]
	return oc, ok
}

// CountAttributeTypes returns how many are registered.
func (r *Registry) CountAttributeTypes() int {
	return len(r.attrsByOID)
}

// CountObjectClasses returns how many are registered.
func (r *Registry) CountObjectClasses() int {
	return len(r.ocsByOID)
}
