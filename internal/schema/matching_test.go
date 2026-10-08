package schema

import "testing"

// Each expectation here comes from reading the C, named in the
// comment, rather than from the RFC.

// UTF8StringNormalize collapses runs of spaces and trims the
// edges — except that a value of nothing but spaces becomes a
// *single space*, not empty (schema_init.c:1934-1939). An
// implementation using strings.Fields gets that one wrong.
func TestUTF8NormalizeSpaces(t *testing.T) {
	ignore := normaliseUTF8(true)
	cases := []struct{ in, want string }{
		{"a b", "a b"},
		{"a  b", "a b"},
		{"a   b", "a b"},
		{"  lead", "lead"},
		{"trail  ", "trail"},
		{"  both  ", "both"},
		{"", ""},
		{" ", " "},
		{"   ", " "},
		{"\t", "\t"},
	}
	for _, c := range cases {
		got := ignore(c.in, UseValue)
		if got != c.want {
			t.Errorf("%q -> %q, want %q",
				c.in, got, c.want)
		}
	}
}

// Case folding is the only difference between the caseIgnore and
// caseExact families; both share UTF8StringNormalize
// (schema_init.c:1893).
func TestCaseFoldingIsTheOnlyDifference(t *testing.T) {
	ignore := normaliseUTF8(true)
	exact := normaliseUTF8(false)
	if ignore("Foo  Bar", UseValue) != "foo bar" {
		t.Errorf("ignore = %q",
			ignore("Foo  Bar", UseValue))
	}
	if exact("Foo  Bar", UseValue) != "Foo Bar" {
		t.Errorf("exact = %q",
			exact("Foo  Bar", UseValue))
	}
	// Full Unicode folding, not ASCII.
	if ignore("Ω", UseValue) != "ω" {
		t.Error("Unicode case folding not applied")
	}
}

// Trimming depends on which substring fragment is being
// normalised: an `any` fragment keeps both edges, `initial`
// keeps its trailing space, `final` keeps its leading one.
func TestSubstringTrimming(t *testing.T) {
	n := normaliseUTF8(true)
	cases := []struct {
		use  Use
		in   string
		want string
	}{
		{UseValue, " x ", "x"},
		{UseSubstringInitial, " x ", "x "},
		{UseSubstringAny, " x ", " x "},
		{UseSubstringFinal, " x ", " x"},
	}
	for _, c := range cases {
		if got := n(c.in, c.use); got != c.want {
			t.Errorf("use %d: %q -> %q, want %q",
				c.use, c.in, got, c.want)
		}
	}
}

// numericStringNormalize removes every space, and an all-space
// value becomes one space.
func TestNumericStringNormalize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1 2 3", "123"},
		{" 42 ", "42"},
		{"  ", " "},
	}
	for _, c := range cases {
		got := normaliseNumericString(c.in, UseValue)
		if got != c.want {
			t.Errorf("%q -> %q, want %q",
				c.in, got, c.want)
		}
	}
}

// telephoneNumberNormalize strips spaces and hyphens and does
// *not* fold case, which the placeholder this replaced got wrong.
func TestTelephoneNormalize(t *testing.T) {
	got := normaliseTelephone("+44 20-7123 4567", UseValue)
	if got != "+442071234567" {
		t.Errorf("got %q", got)
	}
	if normaliseTelephone("ABC", UseValue) != "ABC" {
		t.Error("telephone normalisation folded case")
	}
	if normaliseTelephone(" - ", UseValue) != " " {
		t.Error("all-stripped value should become a space")
	}
}

// integerMatch orders numerically, which a string comparison
// does not: "10" must sort after "9".
func TestIntegerOrdering(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"9", "10", -1},
		{"10", "9", 1},
		{"10", "10", 0},
		{"-1", "1", -1},
		{"-10", "-9", -1},
		{"-9", "-10", 1},
		{"0", "0", 0},
		{"-1", "0", -1},
		{"100", "99", 1},
	}
	for _, c := range cases {
		got := sign(compareInteger(c.a, c.b))
		if got != c.want {
			t.Errorf("compare(%q,%q) = %d, want %d",
				c.a, c.b, got, c.want)
		}
	}
}

// sign reduces a comparison to -1, 0 or 1.
func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
