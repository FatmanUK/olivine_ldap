package ldap

// Search scopes, from include/ldap.h:594-602.
//
// ScopeSubordinate is an OpenLDAP extension, not RFC 4511, and
// is carried because behaviour compatibility is the goal.
type Scope int32

const (
	ScopeBase        Scope = 0
	ScopeOneLevel    Scope = 1
	ScopeSubtree     Scope = 2
	ScopeSubordinate Scope = 3
	ScopeDefault     Scope = -1
)

// String names the scope as ldapsearch spells it.
func (s Scope) String() string {
	switch s {
	case ScopeBase:
		return "base"
	case ScopeOneLevel:
		return "one"
	case ScopeSubtree:
		return "sub"
	case ScopeSubordinate:
		return "children"
	case ScopeDefault:
		return "default"
	}
	return "unknown"
}

// Valid reports whether s is a scope the server accepts. The
// default scope is a client-side marker and is not valid on
// the wire.
func (s Scope) Valid() bool {
	switch s {
	case ScopeBase, ScopeOneLevel, ScopeSubtree,
		ScopeSubordinate:
		return true
	}
	return false
}
