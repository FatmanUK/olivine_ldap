package store

import (
	"crypto/sha1"
	"encoding/base64"
	"testing"
)

// The hash Olivine writes must verify, and the parameters must
// be the ones upstream's pwmods/argon2.c uses so the two
// implementations can read each other's hashes.
func TestArgon2RoundTrip(t *testing.T) {
	hashed, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hashed, "correct horse") {
		t.Error("the password it just hashed did not verify")
	}
	if VerifyPassword(hashed, "wrong horse") {
		t.Error("a wrong password verified")
	}
}

func TestArgon2HashShape(t *testing.T) {
	hashed, err := HashPassword("x")
	if err != nil {
		t.Fatal(err)
	}
	// {ARGON2} is the prefix upstream writes, from
	// slapd_argon2_scheme in pwmods/argon2.c.
	want := "{ARGON2}$argon2id$v=19$m=7168,t=5,p=1$"
	if len(hashed) < len(want) ||
		hashed[:len(want)] != want {
		t.Errorf("hash = %q, want prefix %q", hashed, want)
	}
}

// Cost parameters are read from the hash, not assumed, so a
// value written with other settings still verifies.
func TestArgon2HonoursStoredParameters(t *testing.T) {
	// m=8,t=1,p=1 is far too weak to use, which is the point:
	// if the parameters were hardcoded this would fail.
	salt := []byte("0123456789abcdef")
	b64 := base64.RawStdEncoding
	key := argon2KeyWith("pw", salt,
		argonParams{memory: 8, time: 1, threads: 1}, 32)
	stored := "{ARGON2}$argon2id$v=19$m=8,t=1,p=1$" +
		b64.EncodeToString(salt) + "$" +
		b64.EncodeToString(key)
	if !VerifyPassword(stored, "pw") {
		t.Error("stored parameters were ignored")
	}
}

// Legacy schemes are read but never written, so a directory's
// existing users can still authenticate.
func TestLegacySHA(t *testing.T) {
	sum := sha1.Sum([]byte("secret"))
	stored := "{SHA}" +
		base64.StdEncoding.EncodeToString(sum[:])
	if !VerifyPassword(stored, "secret") {
		t.Error("{SHA} did not verify")
	}
	if VerifyPassword(stored, "wrong") {
		t.Error("{SHA} verified a wrong password")
	}
}

func TestLegacySSHA(t *testing.T) {
	salt := []byte("NaCl")
	h := sha1.New()
	h.Write([]byte("secret"))
	h.Write(salt)
	blob := append(h.Sum(nil), salt...)
	stored := "{SSHA}" +
		base64.StdEncoding.EncodeToString(blob)
	if !VerifyPassword(stored, "secret") {
		t.Error("{SSHA} did not verify")
	}
	if VerifyPassword(stored, "wrong") {
		t.Error("{SSHA} verified a wrong password")
	}
}

// An unknown scheme must fail closed, not fall through to
// comparing the password against the hash text.
func TestUnknownSchemeFailsClosed(t *testing.T) {
	stored := "{BCRYPT}$2y$10$abcdefghijklmnopqrstuv"
	if VerifyPassword(stored, "anything") {
		t.Error("unknown scheme verified")
	}
	if VerifyPassword(stored, stored) {
		t.Error("hash text accepted as the password")
	}
}

func TestPlaintextPassword(t *testing.T) {
	if !VerifyPassword("secret", "secret") {
		t.Error("unprefixed value should compare directly")
	}
	if VerifyPassword("secret", "other") {
		t.Error("wrong plaintext verified")
	}
}
