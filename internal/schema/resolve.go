package schema

// NormaliseValue reduces a value to the form its attribute's
// equality rule compares.
//
// An attribute with no resolvable equality rule is left alone,
// which is what slapd does for a rule with no normalizer.
func (r *Registry) NormaliseValue(
	at *AttributeType, value string, use Use,
) string {
	return r.EqualityRule(at).Normalise(value, use)
}

// Validate checks a value against its attribute's syntax.
//
// The syntax is inherited like the matching rules are: cn
// declares no SYNTAX and takes DirectoryString from name.
func (r *Registry) Validate(
	at *AttributeType, value string,
) error {
	oid := r.syntaxOID(at)
	check, ok := validators[oid]
	if !ok {
		return nil
	}
	return check(value)
}

// syntaxOID resolves an attribute's syntax, following SUP.
func (r *Registry) syntaxOID(at *AttributeType) string {
	for depth := 0; at != nil && depth < 16; depth++ {
		if at.SyntaxOID != "" {
			return at.SyntaxOID
		}
		if at.SuperiorOID == "" {
			return ""
		}
		sup, ok := r.AttributeType(at.SuperiorOID)
		if !ok {
			return ""
		}
		at = sup
	}
	return ""
}
