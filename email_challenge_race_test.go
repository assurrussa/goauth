package goauth_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

type pausingAccountStore struct {
	goauth.RuntimeStore
	armed  atomic.Bool
	paused atomic.Bool
	read   chan struct{}
	resume chan struct{}
}

func (s *pausingAccountStore) GetAccount(ctx context.Context, subjectID goauth.SubjectID) (goauth.Account, error) {
	account, err := s.RuntimeStore.GetAccount(ctx, subjectID)
	if err == nil && s.armed.Load() && s.paused.CompareAndSwap(false, true) {
		close(s.read)
		<-s.resume
	}
	return account, err
}

func TestEmailChallengeRejectsEmailChangedAfterAccountRead(t *testing.T) {
	var intercepted *pausingAccountStore
	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		intercepted = &pausingAccountStore{
			RuntimeStore: config.Store,
			read:         make(chan struct{}),
			resume:       make(chan struct{}),
		}
		config.Store = intercepted
	})
	require.NoError(t, err)
	registered := registerAccount(t, fixture, "challenge-race-old@example.test")
	subjectID := registered.Account.Subject.ID
	require.NoError(t, fixture.Runtime.RequestEmailChange(
		context.Background(), subjectID, "challenge-race-new@example.test"))
	changeCode := latestEmailChangeCode(t, fixture)

	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(intercepted.resume) }) }
	t.Cleanup(release)
	intercepted.armed.Store(true)
	result := make(chan error, 1)
	go func() {
		result <- fixture.Runtime.SendEmailChallenge(
			context.Background(), subjectID, goauth.EmailChallengePurposeVerification)
	}()
	select {
	case <-intercepted.read:
	case <-time.After(5 * time.Second):
		t.Fatal("email challenge did not read the account")
	}
	_, err = fixture.Runtime.ConfirmEmailChange(context.Background(), subjectID, changeCode)
	require.NoError(t, err)
	release()
	select {
	case err := <-result:
		require.ErrorIs(t, err, goauth.ErrInvalidIdentifier)
	case <-time.After(5 * time.Second):
		t.Fatal("stale email challenge did not finish")
	}
	for _, event := range fixture.Events.Events() {
		require.NotEqual(t, "email_challenge", event.Type)
	}
}
