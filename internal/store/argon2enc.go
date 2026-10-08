package store

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
)

// HashPassword hashes a password for storage, in the PHC string
// format upstream's argon2 module writes.
//
// This is the only scheme Olivine writes. Legacy schemes are
// read, never written.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2Key(password, salt)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf(
		"%s$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		schemeArgon2, argonMemory, argonTime,
		argonThreads, b64.EncodeToString(salt),
		b64.EncodeToString(key)), nil
}

// verifyArgon2 checks a PHC-format argon2id hash.
//
// The parameters are read from the hash rather than assumed, so
// a value written with different cost settings — by an older
// Olivine, or by slapd with its own configuration — still
// verifies.
func verifyArgon2(rest, presented string) bool {
	parts := strings.Split(rest, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	p, ok := parseArgonParams(parts[3])
	if !ok {
		return false
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false
	}
	got := argon2KeyWith(presented, salt, p, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// argonParams are the cost settings read from a hash.
type argonParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

// parseArgonParams reads "m=7168,t=5,p=1".
func parseArgonParams(s string) (argonParams, bool) {
	var p argonParams
	var m, t, par int
	n, err := fmt.Sscanf(s, "m=%d,t=%d,p=%d", &m, &t, &par)
	if err != nil || n != 3 {
		return p, false
	}
	if m <= 0 || t <= 0 || par <= 0 || par > 255 {
		return p, false
	}
	p.memory = uint32(m)
	p.time = uint32(t)
	p.threads = uint8(par)
	return p, true
}
