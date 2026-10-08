package server

import (
	"context"
	"testing"

	"github.com/FatmanUK/openldap_olivine/internal/ber"
	"github.com/FatmanUK/openldap_olivine/internal/ldap"
)

// Bind, unbind and abandon refuse to be abandoned.
// abandon.c:66-68 names all three.
func TestNotAbandonable(t *testing.T) {
	cases := []struct {
		name string
		tag  ber.Tag
	}{
		{"bind", ldap.ReqBind},
		{"unbind", ldap.ReqUnbind},
		{"abandon", ldap.ReqAbandon},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newInflight()
			ctx := f.start(
				context.Background(), 1, c.tag)
			if f.abandon(1) {
				t.Error("should refuse to abandon")
			}
			if ctx.Err() != nil {
				t.Error("it was cancelled anyway")
			}
			f.done(1)
			f.wait()
		})
	}
}

// A search, by contrast, is abandonable.
func TestSearchIsAbandonable(t *testing.T) {
	f := newInflight()
	f.start(context.Background(), 1, ldap.ReqSearch)
	if !f.abandon(1) {
		t.Error("a search should be abandonable")
	}
	f.done(1)
	f.wait()
}

// An unknown message id does nothing, as abandon.c:49 does.
func TestAbandonUnknownID(t *testing.T) {
	f := newInflight()
	if f.abandon(12345) {
		t.Error("an unknown id should not report success")
	}
}

// An abandonable operation is cancelled.
func TestAbandonCancels(t *testing.T) {
	f := newInflight()
	ctx := f.start(context.Background(), 3,
		ldap.ReqSearch)
	if ctx.Err() != nil {
		t.Fatal("cancelled before it started")
	}
	if !f.abandon(3) {
		t.Fatal("should have abandoned it")
	}
	if ctx.Err() == nil {
		t.Error("the context was not cancelled")
	}
	f.done(3)
}

// A bind cancels everything in flight, because the identity those
// operations were authorised under is about to change.
func TestCancelAll(t *testing.T) {
	f := newInflight()
	a := f.start(context.Background(), 1, ldap.ReqSearch)
	b := f.start(context.Background(), 2, ldap.ReqSearch)
	f.cancelAll()
	if a.Err() == nil || b.Err() == nil {
		t.Error("cancelAll left an operation running")
	}
	f.done(1)
	f.done(2)
	f.wait()
}

// A repeated message id keeps the first operation abandonable
// rather than losing track of it.
func TestRepeatedMessageID(t *testing.T) {
	f := newInflight()
	first := f.start(context.Background(), 5,
		ldap.ReqSearch)
	second := f.start(context.Background(), 5,
		ldap.ReqSearch)
	if !f.abandon(5) {
		t.Fatal("the first should still be abandonable")
	}
	if first.Err() == nil {
		t.Error("the first was not cancelled")
	}
	if second.Err() != nil {
		t.Error("the second should not have been cancelled")
	}
	f.done(5)
	f.done(5)
	f.wait()
}
