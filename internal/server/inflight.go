package server

import (
	"context"
	"sync"

	"github.com/FatmanUK/openldap_olivine/internal/ber"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// inflight tracks the operations running on one connection.
//
// Abandon is cooperative, as it is in slapd: abandon.c sets
// o_abandon and the backend "can periodically check this flag and
// abort the operation at a convenient time". Here the flag is a
// cancelled context, which the store polls between entries the way
// it polls the time limit.
type inflight struct {
	mu  sync.Mutex
	ops map[int32]*operation
	wg  sync.WaitGroup
}

// operation is one running request.
type operation struct {
	tag    ber.Tag
	cancel context.CancelFunc
}

// newInflight returns an empty registry.
func newInflight() *inflight {
	return &inflight{ops: map[int32]*operation{}}
}

// start registers an operation and returns its context.
//
// A message id already in flight is the client's error. slapd's
// abandon finds the first match in its queue; this keeps the
// existing one and gives the newcomer a context nothing can
// cancel, which is the same observable outcome without losing
// track of the original.
func (f *inflight) start(
	parent context.Context, id int32, tag ber.Tag,
) context.Context {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.wg.Add(1)
	if _, busy := f.ops[id]; busy {
		// No cancellable context for the newcomer: the
		// registry already holds one under this id, and
		// replacing it would lose the ability to abandon the
		// operation that got there first. Creating one and
		// dropping the cancel would leak it, which `go vet`
		// catches.
		return parent
	}
	ctx, cancel := context.WithCancel(parent)
	f.ops[id] = &operation{tag: tag, cancel: cancel}
	return ctx
}

// done deregisters an operation.
func (f *inflight) done(id int32) {
	f.mu.Lock()
	if op, ok := f.ops[id]; ok {
		op.cancel()
		delete(f.ops, id)
	}
	f.mu.Unlock()
	f.wg.Done()
}

// abandon cancels one operation, reporting whether it did.
//
// Bind, unbind and abandon cannot be abandoned: abandon.c:66-68
// names all three. An unknown id does nothing at all, as
// abandon.c:49 does — and either way the client gets no response,
// because an abandon never has one.
func (f *inflight) abandon(id int32) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	op, ok := f.ops[id]
	if !ok || notAbandonable(op.tag) {
		return false
	}
	op.cancel()
	return true
}

// notAbandonable reports whether an operation refuses abandon.
func notAbandonable(tag ber.Tag) bool {
	switch tag {
	case ldap.ReqBind, ldap.ReqUnbind, ldap.ReqAbandon:
		return true
	}
	return false
}

// cancelAll abandons everything in flight.
//
// A bind does this before it begins: connection.c:1633-1636 calls
// connection_abandon( conn ) on seeing LDAP_REQ_BIND, because the
// identity the running operations were authorised under is about
// to change.
func (f *inflight) cancelAll() {
	f.mu.Lock()
	for _, op := range f.ops {
		op.cancel()
	}
	f.mu.Unlock()
}

// wait blocks until every operation has finished.
func (f *inflight) wait() {
	f.wg.Wait()
}
