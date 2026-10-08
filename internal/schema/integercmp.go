package schema

import "strings"

// compareInteger is integerMatch from schema_init.c:2546.
//
// The Integer syntax has no normalizer: integerValidate rejects
// a bare "-", "-0", and leading zeros, so every stored value is
// already canonical and a length-then-bytes comparison is a
// numeric one. That is why this works without parsing.
//
// One deliberate divergence. Upstream reads:
//
//	if( BER_BVISEMPTY( &v ) ) vsign = 0;
//	...
//	if( BER_BVISEMPTY( &a ) ) vsign = 0;
//
// The second line sets vsign where it plainly means asign — a
// copy-paste slip that can only fire on an assertion value of
// exactly "-", which integerValidate rejects anyway. Olivine
// sets asign, because replicating a typo that is unreachable
// through a validating path buys no compatibility and would
// mislead whoever reads this next.
func compareInteger(a, b string) int {
	av, asign := splitSign(a)
	bv, bsign := splitSign(b)
	if asign != bsign {
		return asign - bsign
	}
	match := compareMagnitude(av, bv)
	if asign < 0 {
		return -match
	}
	return match
}

// splitSign separates a leading '-' and reports the sign, which
// is zero when nothing follows it.
func splitSign(s string) (string, int) {
	sign := 1
	if strings.HasPrefix(s, "-") {
		sign = -1
		s = s[1:]
	}
	if s == "" {
		return s, 0
	}
	return s, sign
}

// compareMagnitude orders two unsigned decimal strings, shorter
// first and then bytewise.
func compareMagnitude(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}
