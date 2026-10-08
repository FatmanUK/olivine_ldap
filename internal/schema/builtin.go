package schema

import (
	"bufio"
	"embed"
	"strings"
)

//go:embed builtin.ldif
var builtinFS embed.FS

// Builtin registers the schema slapd hardcodes in
// schema_init.c.
//
// This is not optional decoration. core.schema *comments out*
// cn (2.5.4.3) and name (2.5.4.41) precisely because
// schema_init.c defines them in C, so a registry built from the
// .schema files alone cannot resolve `cn` — and every DN needs
// it. Found when internal/dn's first run against slapdn failed
// on cn=admin,dc=example,dc=com with "unknown attribute type".
//
// The set is derived rather than transcribed: see
// scripts/derive-builtin.sh. It is what slapd emits from
// cn=Subschema minus what the .schema files define, so it
// cannot drift from the submodule it came from.
func Builtin(r *Registry) error {
	data, err := builtinFS.ReadFile("builtin.ldif")
	if err != nil {
		return err
	}
	return loadBuiltin(r, string(data))
}

// NewDefaultRegistry returns a Registry holding the built-in
// schema, which is the minimum a server can operate with.
func NewDefaultRegistry() (*Registry, error) {
	r := NewRegistry()
	if err := Builtin(r); err != nil {
		return nil, err
	}
	return r, nil
}

// loadBuiltin reads the derived definitions.
func loadBuiltin(r *Registry, data string) error {
	sc := bufio.NewScanner(strings.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := addBuiltin(r, line); err != nil {
			return err
		}
	}
	return sc.Err()
}

// addBuiltin registers one derived definition.
func addBuiltin(r *Registry, line string) error {
	kind, def, found := strings.Cut(line, " ")
	if !found {
		return ErrSyntax
	}
	switch kind {
	case "attributeTypes":
		at, err := ParseAttributeType(def)
		if err != nil {
			return err
		}
		return r.AddAttributeType(at)
	case "objectClasses":
		oc, err := ParseObjectClass(def)
		if err != nil {
			return err
		}
		return r.AddObjectClass(oc)
	}
	return ErrSyntax
}
