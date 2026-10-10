package store

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/FatmanUK/olivine_ldap/internal/acl"
)

// configAttr describes one settable configuration attribute.
//
// The set is deliberately small. Everything here is something a
// running server can adopt without being restarted; nothing that
// needs a new listener, a new certificate or a new database
// connection is settable, because adopting one of those is not a
// change of configuration but a different process. Those stay in
// the environment — see Config.
type configAttr struct {
	// name is the declared spelling, which is what a
	// diagnostic quotes and what the projection emits.
	name  string
	key   string
	entry string
	// multi reports whether more than one value is allowed.
	multi bool
	// ordered reports whether value order is significant, and
	// so whether a {n} prefix on an added value places it.
	ordered bool
	// check validates one value and returns it in the form to
	// store.
	check func(s *Store, v string) (string, error)
}

// configAttrs is every attribute cn=config will accept a write
// for. An attribute absent from this table is refused, rather
// than stored and ignored.
var configAttrs = []configAttr{
	{
		name: "olcSizeLimit", key: keySizeLimit,
		entry: ConfigDN, check: checkInt,
	}, {
		name: "olcTimeLimit", key: keyTimeLimit,
		entry: ConfigDN, check: checkInt,
	}, {
		name: "olcSuffix", key: keySuffix,
		entry: databaseDN, multi: true, check: checkDN,
	}, {
		name: "olcRootDN", key: keyRootDN,
		entry: databaseDN, check: checkDN,
	}, {
		name: "olcRootPW", key: keyRootPW,
		entry: databaseDN, check: checkPassword,
	}, {
		name: "olcAccess", key: keyAccess,
		entry: databaseDN, multi: true, ordered: true,
		check: checkAccess,
	},
}

// errNotWritable reports an attribute the configuration will not
// accept a write for.
var errNotWritable = errors.New("store: not writable")

// configRefusal carries a refusal whose text is the diagnostic a
// client should see.
//
// A wrapped sentinel would prefix every message with the
// sentinel's own words, and the diagnostic is read by whoever
// ran ldapmodify — so the sentinel is matched through Is and
// kept out of the text.
type configRefusal struct{ text string }

func (e *configRefusal) Error() string { return e.text }

func (e *configRefusal) Is(target error) bool {
	return target == errNotWritable
}

// notWritable builds a refusal.
func notWritable(format string, a ...any) error {
	return &configRefusal{
		text: fmt.Sprintf(format, a...),
	}
}

// findConfigAttr resolves an attribute description against the
// entry being modified.
//
// The entry matters: olcSuffix on cn=config is as wrong as an
// attribute that does not exist, because the projection puts it
// on the database entry and that is where slapd's schema puts it
// too.
func findConfigAttr(
	entry, typ string,
) (configAttr, error) {
	// slapd compares the whole objectClass set before and
	// after and refuses any change to it, with this wording
	// (bconfig.c:6064-6066). Olivine's configuration entries
	// have one shape each, so the answer is the same and the
	// comparison is unnecessary.
	if strings.EqualFold(typ, "objectClass") {
		return configAttr{}, notWritable(
			"objectclass modification disallowed")
	}
	for _, a := range configAttrs {
		if !strings.EqualFold(a.name, typ) {
			continue
		}
		if a.entry != entry {
			return configAttr{}, notWritable(
				"%s does not belong on %s",
				a.name, entry)
		}
		return a, nil
	}
	return configAttr{}, notWritable(
		"%s is not configurable", typ)
}

// checkInt validates a limit.
func checkInt(_ *Store, v string) (string, error) {
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return "", &SyntaxError{Type: v}
	}
	return strconv.Itoa(n), nil
}

// checkDN validates a DN, storing the pretty form.
//
// Pretty rather than normalised, because this is what a client
// reads back and what an operator wrote; the normalised form is
// derived again on load, where it is needed.
func checkDN(s *Store, v string) (string, error) {
	_, pretty, err := s.normalise(v)
	if err != nil {
		return "", err
	}
	return pretty, nil
}

// checkAccess validates one access directive.
//
// The value is stored without its {n} prefix: position is the
// row's sequence number, so keeping the prefix as well would be
// two authorities for one fact.
func checkAccess(_ *Store, v string) (string, error) {
	bare := stripIndex(v)
	if _, err := acl.Parse("access " + bare); err != nil {
		return "", err
	}
	return bare, nil
}

// checkPassword hashes a root password that arrives in the clear.
//
// slapd stores olcRootPW exactly as given, cleartext included,
// and compares with lutil_passwd, which accepts an unhashed
// value. This does not copy that: a password written over LDAP
// is hashed with Argon2id unless it already carries a scheme, so
// the table never holds a recoverable credential. The divergence
// is visible only to something reading olcRootPW back, and
// nothing can — the projection withholds it.
func checkPassword(_ *Store, v string) (string, error) {
	if strings.HasPrefix(v, "{") &&
		strings.Contains(v, "}") {
		return v, nil
	}
	return HashPassword(v)
}
