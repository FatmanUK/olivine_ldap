package schema

import (
	"fmt"
	"io"
	"strings"
)

// LoadFile reads an OpenLDAP .schema file into r.
//
// The format is not RFC 4512: a definition is introduced by a
// keyword (attributetype, objectclass, objectidentifier,
// ldapsyntax, ditcontentrule), continuation lines are indented,
// and # starts a comment. This is what the files under
// openldap/servers/slapd/schema actually look like, and they
// are the corpus the parser is tested against.
//
// Keywords are case-insensitive: dyngroup.schema writes both
// `attributetype` and `attributeType`.
func LoadFile(r *Registry, src io.Reader) error {
	for _, def := range splitDefs(src) {
		if err := r.add(def); err != nil {
			return err
		}
	}
	return nil
}

// add dispatches one definition by its leading keyword.
//
// An unrecognised keyword is skipped rather than refused.
// slapd does the same, silently: a misspelled directive in a
// schema file leaves slaptest reporting success and the
// definition simply absent. Upstream's own dsee.schema:96 says
// `attributeype`, so targetUniqueId is missing from every
// slapd that loads it. Refusing the file here would reject
// input slapd accepts.
func (r *Registry) add(def string) error {
	kw, rest := firstWord(def)
	switch strings.ToLower(kw) {
	case "attributetype":
		return r.addAttr(rest)
	case "objectclass":
		return r.addOC(rest)
	case "objectidentifier":
		return r.addMacro(rest)
	case "ldapsyntax", "ditcontentrule", "ditstructurerule",
		"nameform", "matchingrule", "matchingruleuse":
		r.skip(kw, "definition type not modelled yet", rest)
		return nil
	}
	r.skip(kw, "unknown keyword", rest)
	return nil
}

// skip records an unregistered definition.
func (r *Registry) skip(kw, reason, snippet string) {
	if len(snippet) > 60 {
		snippet = snippet[:60]
	}
	r.Skipped = append(r.Skipped, Skip{
		Keyword: kw, Reason: reason, Snippet: snippet,
	})
}

// addAttr parses and registers an attribute type.
func (r *Registry) addAttr(rest string) error {
	at, err := ParseAttributeType(rest)
	if err != nil {
		return fmt.Errorf("%w in %.60s", err, rest)
	}
	at.OID, err = r.macros.resolve(at.OID)
	if err != nil {
		return err
	}
	return r.AddAttributeType(at)
}

// addOC parses and registers an object class.
func (r *Registry) addOC(rest string) error {
	oc, err := ParseObjectClass(rest)
	if err != nil {
		return fmt.Errorf("%w in %.60s", err, rest)
	}
	oc.OID, err = r.macros.resolve(oc.OID)
	if err != nil {
		return err
	}
	return r.AddObjectClass(oc)
}

// addMacro records an objectIdentifier declaration.
func (r *Registry) addMacro(rest string) error {
	name, value := firstWord(rest)
	if name == "" || value == "" {
		return fmt.Errorf("%w: objectIdentifier %q",
			ErrSyntax, rest)
	}
	return r.macros.define(name, value)
}

// firstWord splits off the leading keyword.
func firstWord(s string) (string, string) {
	s = strings.TrimSpace(s)
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimSpace(s[i:])
}
