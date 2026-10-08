package server

// Per-connection limits, from servers/slapd/slap.h:142-146.
//
// Each has an unauthenticated and an authenticated value, and
// the authenticated one is larger. A connection that has bound
// is trusted with more, which is the whole pattern: the cheap
// limits apply to anyone who can open a socket.
const (
	MaxPendingDefault = 100
	MaxPendingAuth    = 1000
)
