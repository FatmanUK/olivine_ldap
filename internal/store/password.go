package store

import (
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters, matching upstream's pwmods/argon2.c:
// SLAPD_ARGON2_ITERATIONS 5, MEMORY 7168 (KiB), PARALLELISM 1,
// SALT_LENGTH 16, HASH_LENGTH 32.
//
// Matched deliberately. Olivine's divergence is making argon2id
// the *default* write scheme — upstream ships it as an optional
// loadable module — not changing the format, so hashes stay
// mutually readable between the two implementations.
const (
	argonTime    = 5
	argonMemory  = 7168
	argonThreads = 1
	argonSaltLen = 16
	argonKeyLen  = 32
)

// schemeArgon2 is the prefix upstream writes, from
// `const struct berval slapd_argon2_scheme =
// BER_BVC("{ARGON2}")`.
const schemeArgon2 = "{ARGON2}"

// VerifyPassword checks a presented password against a stored
// value.
//
// Legacy schemes are read but never written, as BOOTSTRAP.md
// §3.3 records: a directory that cannot authenticate its
// existing users is not compatible with anything.
func VerifyPassword(stored, presented string) bool {
	scheme, rest := splitScheme(stored)
	switch scheme {
	case schemeArgon2:
		return verifyArgon2(rest, presented)
	case "{SSHA}":
		return verifySSHA(rest, presented)
	case "{SHA}":
		return verifySHA(rest, presented)
	case "":
		// No prefix: the value is the password itself.
		// slapd accepts this, and constant-time comparison
		// matters as much here as anywhere.
		return constantEqual(stored, presented)
	}
	// An unknown scheme fails closed rather than falling back
	// to a plaintext comparison against the hash.
	return false
}

// splitScheme separates a {SCHEME} prefix from the rest.
func splitScheme(s string) (string, string) {
	if !strings.HasPrefix(s, "{") {
		return "", s
	}
	end := strings.Index(s, "}")
	if end < 0 {
		return "", s
	}
	return strings.ToUpper(s[:end+1]), s[end+1:]
}

// constantEqual compares without leaking length-independent
// timing.
func constantEqual(a, b string) bool {
	return subtle.ConstantTimeCompare(
		[]byte(a), []byte(b)) == 1
}

// verifySHA checks an unsalted {SHA} hash.
func verifySHA(encoded, presented string) bool {
	want, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(want) != sha1.Size {
		return false
	}
	sum := sha1.Sum([]byte(presented))
	return subtle.ConstantTimeCompare(
		sum[:], want) == 1
}

// verifySSHA checks a salted {SSHA} hash, where the salt
// follows the digest in the same base64 blob.
func verifySSHA(encoded, presented string) bool {
	blob, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(blob) <= sha1.Size {
		return false
	}
	digest, salt := blob[:sha1.Size], blob[sha1.Size:]
	h := sha1.New()
	h.Write([]byte(presented))
	h.Write(salt)
	return subtle.ConstantTimeCompare(
		h.Sum(nil), digest) == 1
}

// argon2Key derives a key with Olivine's parameters.
func argon2Key(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt,
		argonTime, argonMemory, argonThreads,
		argonKeyLen)
}

// argon2KeyWith derives a key with the parameters read from a
// stored hash.
func argon2KeyWith(
	password string, salt []byte, p argonParams, n int,
) []byte {
	return argon2.IDKey([]byte(password), salt,
		p.time, p.memory, p.threads, uint32(n))
}
