package server

import (
	"testing"
	"time"

	"github.com/FatmanUK/openldap_olivine/internal/ber"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// slowBackend blocks a search until released, so a test can
// abandon one mid-flight.
type slowBackend struct {
	*fakeBackend
	entered  chan struct{}
	release  chan struct{}
	finished chan struct{}
}

// newSlow returns a backend whose searches block.
func newSlow() *slowBackend {
	return &slowBackend{
		fakeBackend: newFake(),
		entered:     make(chan struct{}, 1),
		release:     make(chan struct{}),
		finished:    make(chan struct{}, 1),
	}
}

// Search blocks until released, then reports whether its context
// was cancelled while it waited.
func (b *slowBackend) Search(
	r *ldap.SearchRequest, who ldap.Identity,
) ([]ldap.SearchEntry, ldap.Result, []ldap.Control) {
	b.entered <- struct{}{}
	<-b.release
	if r.Context != nil && r.Context.Err() != nil {
		b.finished <- struct{}{}
		return nil, ldap.Result{Code: ldap.Other}, nil
	}
	b.finished <- struct{}{}
	return b.entries, b.result, nil
}

// abandonBody encodes an abandon for one message id.
//
// The body is the id on its own, which is why ReqAbandon carries a
// primitive tag: RFC 4511 4.11 makes it [APPLICATION 16] MessageID.
func abandonBody(t *testing.T, id int32) []byte {
	t.Helper()
	e := ber.NewEncoder()
	e.Begin(ldap.TagMessage)
	e.Int32(ldap.TagMsgID, 99)
	e.Raw(ldap.ReqAbandon, encodeID(id))
	e.End()
	out, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// encodeID renders a bare message id.
func encodeID(id int32) []byte {
	e := ber.NewEncoder()
	e.Int32(ber.TagInteger, id)
	out, err := e.Bytes()
	if err != nil {
		panic(err)
	}
	// Strip the tag and length: the body is the integer's
	// contents, not a nested element.
	_, content, err := ber.NewDecoder(out).Next()
	if err != nil {
		panic(err)
	}
	return content
}

// An abandoned search sends nothing at all: not the entries it
// found and not a result. RFC 4511 4.11 gives an abandoned
// operation no response.
func TestAbandonSuppressesTheResponse(t *testing.T) {
	slow := newSlow()
	slow.entries = []ldap.SearchEntry{{DN: "cn=x"}}
	_, cliTLS, addr := startWith(t, slow)
	c := dial(t, cliTLS, addr)

	if _, err := c.Write(envelope(
		t, 1, ldap.ReqSearch, searchBody(t))); err != nil {
		t.Fatal(err)
	}
	<-slow.entered
	// Abandon it while it is still running.
	if _, err := c.Write(abandonBody(t, 1)); err != nil {
		t.Fatal(err)
	}
	// Give the abandon time to be read and applied, then let
	// the search finish.
	time.Sleep(100 * time.Millisecond)
	close(slow.release)
	<-slow.finished

	// Nothing should arrive. A short deadline distinguishes
	// "no reply" from "slow reply".
	if err := c.SetDeadline(
		time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if n, err := c.Read(buf); err == nil {
		t.Fatalf("an abandoned search replied (%d bytes)", n)
	}
}

// Abandon never has a response of its own, found or not.
func TestAbandonItselfIsSilent(t *testing.T) {
	fake := newFake()
	_, cliTLS, addr := startWith(t, fake)
	c := dial(t, cliTLS, addr)

	// Nothing is running under id 7.
	if _, err := c.Write(abandonBody(t, 7)); err != nil {
		t.Fatal(err)
	}
	if err := c.SetDeadline(
		time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("abandon drew a reply")
	}
}

// Operations run concurrently, so a client can pipeline: a slow
// search must not stop a later request being read and answered.
func TestOperationsRunConcurrently(t *testing.T) {
	slow := newSlow()
	_, cliTLS, addr := startWith(t, slow)
	c := dial(t, cliTLS, addr)

	if _, err := c.Write(envelope(
		t, 1, ldap.ReqSearch, searchBody(t))); err != nil {
		t.Fatal(err)
	}
	<-slow.entered
	// A delete while the search is still blocked.
	e := ber.NewEncoder()
	e.Begin(ldap.TagMessage)
	e.Int32(ldap.TagMsgID, 2)
	e.OctetString(ldap.ReqDelete, []byte("cn=y,dc=x"))
	e.End()
	packet, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(packet); err != nil {
		t.Fatal(err)
	}
	m := readMessage(t, c)
	if m.ID != 2 || m.Op != ldap.ResDelete {
		t.Fatalf("id = %d, op = %#x; the second request "+
			"should have been answered first", m.ID, m.Op)
	}
	close(slow.release)
	<-slow.finished
}
