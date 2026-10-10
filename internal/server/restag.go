package server

import (
	"github.com/FatmanUK/olivine_ldap/internal/ber"
	"github.com/FatmanUK/olivine_ldap/internal/ldap"
)

// responseTag maps a request tag to the tag its response
// carries, from ldap.h:522-548.
//
// The pairs are not a simple offset. Bind is 0x60/0x61 and Add
// is 0x68/0x69, but Delete is 0x4a/0x6b and ModDN is
// 0x6c/0x6d, so arithmetic on the request tag would be wrong
// for exactly the operations whose requests are primitive.
var responseTags = map[ber.Tag]ber.Tag{
	ldap.ReqBind:     ldap.ResBind,
	ldap.ReqSearch:   ldap.ResSearchResult,
	ldap.ReqModify:   ldap.ResModify,
	ldap.ReqAdd:      ldap.ResAdd,
	ldap.ReqDelete:   ldap.ResDelete,
	ldap.ReqModDN:    ldap.ResModDN,
	ldap.ReqCompare:  ldap.ResCompare,
	ldap.ReqExtended: ldap.ResExtended,
}

// responseTag returns the response tag for req. Unbind and
// abandon have no response and are not in the table; callers
// must not reach here with them.
func responseTag(req ber.Tag) ber.Tag {
	if t, ok := responseTags[req]; ok {
		return t
	}
	return ldap.ResExtended
}
