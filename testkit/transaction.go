package testkit

import (
	"context"
	"errors"
	"maps"

	"github.com/assurrussa/goauth"
)

type (
	storeScopeKey struct{}
	storeScope    struct{ original, working *Store }
	eventScopeKey struct{}
	eventScope    struct{ original, working *EventSink }
)

var errForeignStoreTransaction = errors.New("auth transaction belongs to a different testkit store")

func (s *Store) validateTransactionScope(ctx context.Context) error {
	if scope, ok := ctx.Value(storeScopeKey{}).(storeScope); ok && scope.original != s {
		return errForeignStoreTransaction
	}
	return nil
}

func (s *Store) scoped(ctx context.Context) *Store {
	if scope, ok := ctx.Value(storeScopeKey{}).(storeScope); ok && scope.original == s {
		return scope.working
	}
	return s
}

func (s *EventSink) scoped(ctx context.Context) *EventSink {
	if scope, ok := ctx.Value(eventScopeKey{}).(eventScope); ok && scope.original == s {
		return scope.working
	}
	return s
}

// InAuthTransaction serializes store operations and publishes a private snapshot
// only on success. The fixture additionally enlists its encrypted event sink.
func (s *Store) InAuthTransaction(ctx context.Context, fn func(context.Context) error) error {
	if err := s.validateTransactionScope(ctx); err != nil {
		return err
	}
	if s.scoped(ctx) != s {
		return fn(ctx)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	working := s.snapshot()
	if err := fn(context.WithValue(ctx, storeScopeKey{}, storeScope{s, working})); err != nil {
		return err
	}
	s.audits = working.audits
	s.accounts = working.accounts
	s.retired = working.retired
	s.identifiers = working.identifiers
	s.localIdentifiers = working.localIdentifiers
	s.passwords = working.passwords
	s.passwordPolicies = working.passwordPolicies
	s.links = working.links
	s.sessions = working.sessions
	s.families = working.families
	s.refresh = working.refresh
	s.resets = working.resets
	s.challenges = working.challenges
	s.emailChanges = working.emailChanges
	// TakeRateLimit rejects this scope before taking the same mutex. No
	// independently admitted attempt can be overwritten by this snapshot.
	// Email-issue quotas remain transactional and roll back with their writes.
	s.rateEvents = working.rateEvents
	return nil
}

type fixtureTransaction struct {
	store  *Store
	events *EventSink
}

func (t *fixtureTransaction) InAuthTransaction(ctx context.Context, fn func(context.Context) error) error {
	if err := t.store.validateTransactionScope(ctx); err != nil {
		return err
	}
	if t.store.scoped(ctx) != t.store {
		return fn(ctx)
	}
	return t.store.InAuthTransaction(ctx, func(ctx context.Context) error {
		t.events.mu.Lock()
		defer t.events.mu.Unlock()
		working := &EventSink{}
		for _, e := range t.events.events {
			working.events = append(working.events, cloneEvent(e))
		}
		if err := fn(context.WithValue(ctx, eventScopeKey{}, eventScope{t.events, working})); err != nil {
			return err
		}
		t.events.events = working.events
		return nil
	})
}

func copyPointers[K comparable, V any](src map[K]*V) map[K]*V {
	dst := make(map[K]*V, len(src))
	for k, v := range src {
		c := *v
		dst[k] = &c
	}
	return dst
}

func (s *Store) snapshot() *Store {
	c := NewStore()
	c.audits = append(c.audits, s.audits...)
	for k, v := range s.accounts {
		c.accounts[k] = cloneAccount(v)
	}
	c.retired = maps.Clone(s.retired)
	c.identifiers = maps.Clone(s.identifiers)
	for k, v := range s.localIdentifiers {
		c.localIdentifiers[k] = cloneLocalIdentifier(v)
	}
	c.passwords = maps.Clone(s.passwords)
	c.passwordPolicies = maps.Clone(s.passwordPolicies)
	c.links = maps.Clone(s.links)
	c.sessions = maps.Clone(s.sessions)
	c.families = copyPointers(s.families)
	c.refresh = copyPointers(s.refresh)
	c.resets = copyPointers(s.resets)
	for k, vs := range s.challenges {
		for _, v := range vs {
			x := *v
			c.challenges[k] = append(c.challenges[k], &x)
		}
	}
	for k, vs := range s.emailChanges {
		for _, v := range vs {
			x := *v
			c.emailChanges[k] = append(c.emailChanges[k], &x)
		}
	}
	for k, v := range s.rateEvents {
		c.rateEvents[k] = append(v[:0:0], v...)
	}
	return c
}

var _ goauth.AuthTransaction = (*Store)(nil)
