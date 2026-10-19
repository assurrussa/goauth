package goauth_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

const (
	noticeTestScope     goauth.EmailChangeScope = "notice-host-v1"
	noticeCodeEventType                         = "email_change"
)

type requestedNoticeTarget struct {
	snapshot goauth.EmailChangeTargetSnapshot
}

func (t *requestedNoticeTarget) SnapshotEmailChangeTarget(
	context.Context, goauth.SubjectID,
) (goauth.EmailChangeTargetSnapshot, error) {
	return t.snapshot, nil
}

func (*requestedNoticeTarget) ApplyVerifiedEmailChange(
	context.Context, goauth.SubjectID, goauth.EmailChangeTargetSnapshot, string, time.Time,
) error {
	return nil
}

type requestedNoticeStore struct {
	goauth.RuntimeStore
	status goauth.EmailChangeIssueStatus
	calls  int
}

func (s *requestedNoticeStore) IssueScopedEmailChange(
	_ context.Context, _ goauth.EmailChangeRecord, _ goauth.EmailChallengeLimits,
) (goauth.EmailChangeIssueResult, error) {
	s.calls++
	return goauth.EmailChangeIssueResult{Status: s.status, RetryAt: time.Now().Add(time.Hour)}, nil
}

func (*requestedNoticeStore) GetPendingScopedEmailChange(
	context.Context, goauth.SubjectID, goauth.EmailChangeScope, time.Time,
) (goauth.PendingEmailChange, error) {
	return goauth.PendingEmailChange{}, goauth.ErrEmailChangeNotFound
}

func (*requestedNoticeStore) VerifyScopedEmailChange(
	context.Context, goauth.EmailChangeVerifyRequest,
) (goauth.EmailChangeVerifyResult, error) {
	return goauth.EmailChangeVerifyResult{}, goauth.ErrEmailChangeNotFound
}

func requestedNoticeFixture(
	t *testing.T, status goauth.EmailChangeIssueStatus,
) (*testkit.Fixture, *requestedNoticeStore, context.Context) {
	t.Helper()
	var probe *requestedNoticeStore
	fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
		probe = &requestedNoticeStore{RuntimeStore: c.Store, status: status}
		c.Store = probe
		c.ManagedNotificationDelivery = true
		c.EmailChangeTargets = map[goauth.EmailChangeScope]goauth.EmailChangeTarget{
			noticeTestScope: &requestedNoticeTarget{snapshot: goauth.EmailChangeTargetSnapshot{
				NormalizedEmail: "old-alias@example.test", Version: 4,
			}},
		}
	})
	require.NoError(t, err)
	return fixture, probe, goauth.WithEmailChangeScope(context.Background(), noticeTestScope)
}

func noticeEvents(fixture *testkit.Fixture) []goauth.EncryptedEvent {
	var result []goauth.EncryptedEvent
	for _, event := range fixture.Events.Events() {
		if event.Type == "email_change_requested" {
			result = append(result, event)
		}
	}
	return result
}

func TestPreviousEmailNoticeIssuedIsEncryptedCredentialFreeAndHistorical(t *testing.T) {
	f, _, ctx := requestedNoticeFixture(t, goauth.EmailChangeIssued)
	account := registerAccount(t, f, "primary@example.test").Account
	require.NoError(t, f.Runtime.RequestEmailChangeWithPreviousEmailNotice(
		ctx, account.Subject.ID, "new@example.test", "old-alias@example.test"))
	notices := noticeEvents(f)
	require.Len(t, notices, 1)
	event := notices[0]
	require.NotEmpty(t, event.ID)
	require.NotEmpty(t, event.ReferenceID)
	notice, err := f.Runtime.DecryptNotificationEvent(event)
	require.NoError(t, err)
	require.Equal(t, "email_change_requested", notice.Template)
	require.Equal(t, "old-alias@example.test", notice.To)
	require.Equal(t, map[string]string{"email_change_scope": string(noticeTestScope)}, notice.Data)
	require.False(t, bytes.Contains(event.Envelope.Ciphertext, []byte(notice.To)))
	var codeEvent goauth.EncryptedEvent
	for _, e := range f.Events.Events() {
		if e.Type == noticeCodeEventType {
			codeEvent = e
		}
	}
	require.NotEmpty(t, codeEvent.ID)
	require.NotEqual(t, codeEvent.ID, event.ID)
	require.Equal(t, codeEvent.ReferenceID, event.ReferenceID)
	require.True(t, event.ValidUntil.After(codeEvent.ValidUntil))
	codeMail, err := f.Runtime.DecryptNotificationEvent(codeEvent)
	require.NoError(t, err)
	require.Equal(t, "new@example.test", codeMail.To)
	require.Len(t, codeMail.Data["code"], 6)
	require.NotContains(t, notice.Data, "code")
	// A new issuance creates another historical notice, never mutates the old event.
	require.NoError(t, f.Runtime.RequestEmailChangeWithPreviousEmailNotice(
		ctx, account.Subject.ID, "next@example.test", "old-alias@example.test"))
	require.Equal(t, event, noticeEvents(f)[0])
}

func TestPreviousEmailNoticeOnlyForIssued(t *testing.T) {
	for _, tc := range []struct {
		status goauth.EmailChangeIssueStatus
		want   error
	}{
		{goauth.EmailChangeSameValue, goauth.ErrEmailChangeSameValue},
		{goauth.EmailChangeWait, goauth.ErrConfirmationResendDelay},
		{goauth.EmailChangeHourlyLimit, goauth.ErrConfirmationRateLimited},
		{goauth.EmailChangeDailyLimit, goauth.ErrConfirmationRateLimited},
	} {
		t.Run(string(tc.status), func(t *testing.T) {
			f, _, ctx := requestedNoticeFixture(t, tc.status)
			account := registerAccount(t, f, "primary@example.test").Account
			before := len(f.Events.Events())
			err := f.Runtime.RequestEmailChangeWithPreviousEmailNotice(
				ctx, account.Subject.ID, "new@example.test", "old-alias@example.test")
			require.ErrorIs(t, err, tc.want)
			require.Len(t, f.Events.Events(), before)
		})
	}
}

func TestPreviousEmailNoticeRejectsWrongOrNonCanonicalOldBeforeIssuance(t *testing.T) {
	for _, old := range []string{"other@example.test", "OLD-ALIAS@example.test", " old-alias@example.test", "invalid"} {
		t.Run(old, func(t *testing.T) {
			f, probe, ctx := requestedNoticeFixture(t, goauth.EmailChangeIssued)
			account := registerAccount(t, f, "primary@example.test").Account
			before := len(f.Events.Events())
			require.Error(t, f.Runtime.RequestEmailChangeWithPreviousEmailNotice(
				ctx, account.Subject.ID, "new@example.test", old))
			require.Zero(t, probe.calls)
			require.Len(t, f.Events.Events(), before)
		})
	}
}

func TestPreviousEmailNoticeEmptyAndExistingAPIRetainBehavior(t *testing.T) {
	for _, oldAPI := range []bool{false, true} {
		f, _, ctx := requestedNoticeFixture(t, goauth.EmailChangeIssued)
		account := registerAccount(t, f, "primary@example.test").Account
		var err error
		if oldAPI {
			err = f.Runtime.RequestEmailChange(ctx, account.Subject.ID, "new@example.test")
		} else {
			err = f.Runtime.RequestEmailChangeWithPreviousEmailNotice(ctx, account.Subject.ID, "new@example.test", "")
		}
		require.NoError(t, err)
		require.Empty(t, noticeEvents(f))
	}
}

func TestPreviousEmailNoticeEnqueueFailureRollsBackCodeAndIssuance(t *testing.T) {
	var reject bool
	f, err := testkit.NewRuntime(func(c *goauth.Config) {
		c.ManagedNotificationDelivery = true
		c.EventSink = rejectRequestedNoticeSink{EncryptedEventSink: c.EventSink, reject: &reject}
	})
	require.NoError(t, err)
	account := registerAccount(t, f, "old@example.test").Account
	require.NoError(t, f.Runtime.SendEmailChallenge(
		context.Background(), account.Subject.ID, goauth.EmailChallengePurposeVerification,
	))
	_, err = f.Runtime.VerifyEmailChallenge(
		context.Background(), account.Subject.ID, goauth.EmailChallengePurposeVerification, latestChallengeCode(t, f),
	)
	require.NoError(t, err)
	before := len(f.Events.Events())
	reject = true
	require.Error(t, f.Runtime.RequestEmailChangeWithPreviousEmailNotice(
		context.Background(), account.Subject.ID, "new@example.test", "old@example.test",
	))
	require.Len(t, f.Events.Events(), before)
	_, err = f.Runtime.PendingEmailChange(context.Background(), account.Subject.ID)
	require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
	reject = false
	require.NoError(t, f.Runtime.RequestEmailChangeWithPreviousEmailNotice(
		context.Background(), account.Subject.ID, "new@example.test", "old@example.test",
	))
	require.Len(t, noticeEvents(f), 1)
}

type rejectRequestedNoticeSink struct {
	goauth.EncryptedEventSink
	reject *bool
}

func (s rejectRequestedNoticeSink) EnqueueEncrypted(ctx context.Context, event goauth.EncryptedEvent) error {
	if *s.reject && event.Type == "email_change_requested" {
		return errors.New("injected notice failure")
	}
	return s.EncryptedEventSink.EnqueueEncrypted(ctx, event)
}

type unknownRequestedNoticeCommit struct {
	goauth.AuthTransaction
	armed bool
}

func (tx *unknownRequestedNoticeCommit) InAuthTransaction(ctx context.Context, fn func(context.Context) error) error {
	err := tx.AuthTransaction.InAuthTransaction(ctx, fn)
	if err == nil && tx.armed {
		tx.armed = false
		return goauth.ErrOperationOutcomeUnknown
	}
	return err
}

func TestPreviousEmailNoticeUnknownCommitRetainsOneStableEncryptedEvent(t *testing.T) {
	var tx *unknownRequestedNoticeCommit
	f, err := testkit.NewRuntime(func(c *goauth.Config) {
		tx = &unknownRequestedNoticeCommit{AuthTransaction: c.AuthTransaction}
		c.AuthTransaction = tx
		c.ManagedNotificationDelivery = true
	})
	require.NoError(t, err)
	account := registerAccount(t, f, "old@example.test").Account
	require.NoError(t, f.Runtime.SendEmailChallenge(
		context.Background(), account.Subject.ID, goauth.EmailChallengePurposeVerification,
	))
	_, err = f.Runtime.VerifyEmailChallenge(
		context.Background(), account.Subject.ID, goauth.EmailChallengePurposeVerification, latestChallengeCode(t, f),
	)
	require.NoError(t, err)
	tx.armed = true
	err = f.Runtime.RequestEmailChangeWithPreviousEmailNotice(
		context.Background(), account.Subject.ID, "new@example.test", "old@example.test",
	)
	require.ErrorIs(t, err, goauth.ErrOperationOutcomeUnknown)
	notices := noticeEvents(f)
	require.Len(t, notices, 1)
	_, err = f.Runtime.DecryptNotificationEvent(notices[0])
	require.NoError(t, err)
	// Existing issuance admission rejects an immediate caller retry. The API
	// does not claim exactly-once semantics for a later independent request.
	err = f.Runtime.RequestEmailChangeWithPreviousEmailNotice(
		context.Background(), account.Subject.ID, "new@example.test", "old@example.test",
	)
	require.ErrorIs(t, err, goauth.ErrConfirmationResendDelay)
	require.Equal(t, notices, noticeEvents(f))
}

func TestPreviousEmailNoticePrimaryRequiresVerifiedAddress(t *testing.T) {
	f := newFixture(t)
	account := registerAccount(t, f, "old@example.test").Account
	require.ErrorIs(t, f.Runtime.RequestEmailChangeWithPreviousEmailNotice(
		context.Background(), account.Subject.ID, "new@example.test", "old@example.test"), goauth.ErrInvalidIdentifier)
	require.Empty(t, noticeEvents(f))
}

func TestPreviousEmailNoticeSurvivesConfirmationAndLaterIssuance(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	f, err := testkit.NewRuntime(func(c *goauth.Config) {
		c.ManagedNotificationDelivery = true
		c.Now = func() time.Time { return now }
	})
	require.NoError(t, err)
	ctx := context.Background()
	account := registerAccount(t, f, "old@example.test").Account
	require.NoError(t, f.Runtime.SendEmailChallenge(ctx, account.Subject.ID, goauth.EmailChallengePurposeVerification))
	_, err = f.Runtime.VerifyEmailChallenge(
		ctx, account.Subject.ID, goauth.EmailChallengePurposeVerification, latestChallengeCode(t, f),
	)
	require.NoError(t, err)
	require.NoError(t, f.Runtime.RequestEmailChangeWithPreviousEmailNotice(
		ctx, account.Subject.ID, "new@example.test", "old@example.test",
	))
	notice := noticeEvents(f)[0]
	var code string
	for _, event := range f.Events.Events() {
		if event.Type == noticeCodeEventType {
			mail, err := f.Runtime.DecryptNotificationEvent(event)
			require.NoError(t, err)
			code = mail.Data["code"]
		}
	}
	require.Len(t, code, 6)
	_, err = f.Runtime.ConfirmEmailChange(ctx, account.Subject.ID, code)
	require.NoError(t, err)
	require.Equal(t, notice, noticeEvents(f)[0])
	now = now.Add(2 * time.Minute)
	require.NoError(t, f.Runtime.RequestEmailChangeWithPreviousEmailNotice(
		ctx, account.Subject.ID, "next@example.test", "new@example.test",
	))
	require.Len(t, noticeEvents(f), 2)
	require.Equal(t, notice, noticeEvents(f)[0])
	oldMail, err := f.Runtime.DecryptNotificationEvent(notice)
	require.NoError(t, err)
	require.Equal(t, "old@example.test", oldMail.To)
	require.Empty(t, oldMail.Data)
}
