package dn

import (
	"github.com/FatmanUK/openldap_olivine/internal/schema"
)

// normaliseValue applies the attribute's equality matching rule
// to a value.
//
// The rules now live in internal/schema, which replaced the
// hand-written list of case-insensitive rule names this file used
// to carry. That list was both incomplete and wrong in one place:
// it treated telephoneNumberMatch as case-folding, where
// telephoneNumberNormalize in schema_init.c strips spaces and
// hyphens and leaves case alone.
//
// Behaviour against slapdn is unchanged, which is the point: the
// captured corpus passed before and still passes, so the real
// rules agree with the approximation wherever the approximation
// was right.
func normaliseValue(
	r *schema.Registry, at *schema.AttributeType,
	value string,
) string {
	return r.NormaliseValue(at, value, schema.UseValue)
}
