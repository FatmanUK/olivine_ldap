package store

import (
	"github.com/FatmanUK/olivine_ldap/internal/ldap"
	"github.com/FatmanUK/olivine_ldap/internal/schema"
)

// wantsUser reports whether the requested list includes user
// attributes.
//
// An empty list and "*" both mean all user attributes, RFC 4511
// 4.5.1.8. A list of only "+" does not: slapd's `+` output carries
// no objectClass line, because "+" selects operational attributes
// and nothing else (RFC 3673).
func wantsUser(attrs []string) bool {
	if len(attrs) == 0 {
		return true
	}
	for _, a := range attrs {
		if a == ldap.AllUserAttributes {
			return true
		}
	}
	return false
}

// wantsOperational reports whether "+" was asked for.
func wantsOperational(attrs []string) bool {
	for _, a := range attrs {
		if a == ldap.AllOperationalAttributes {
			return true
		}
	}
	return false
}

// isOperational reports whether an attribute type is operational.
//
// Anything but userApplications is: directoryOperation,
// distributedOperation and dSAOperation are all withheld from a
// plain search.
func isOperational(at *schema.AttributeType) bool {
	return at.Usage != schema.UserApplications
}
