// Package schema holds attribute types, object classes,
// syntaxes and matching rules.
//
// Ported from servers/slapd/{at,oc,syntax,mr,schema_init}.c
// in the openldap submodule. schema_init.c alone is 6,979
// lines, and the normalisation rules in it are where
// behaviour compatibility is won or lost, so it is checked
// line by line rather than paraphrased.
package schema
