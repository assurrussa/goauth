package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/internal/identifierbounds"
)

func (s *Store) GetSubjectLifecycle(ctx context.Context, id goauth.SubjectID) (goauth.SubjectLifecycleView, error) {
	if id.IsZero() {
		return goauth.SubjectLifecycleView{}, goauth.ErrAccountNotFound
	}
	if _, err := s.notificationTx(ctx); err != nil {
		return goauth.SubjectLifecycleView{}, err
	}
	return getSubjectLifecycle(ctx, s.queryer(ctx), id)
}

func getSubjectLifecycle(ctx context.Context, db queryRower, id goauth.SubjectID) (goauth.SubjectLifecycleView, error) {
	// A single SELECT is required even outside a managed transaction: two live
	// READ COMMITTED reads could otherwise combine an active account and tombstone.
	query := `SELECT ` + accountColumns + `, s.retired_at ` + accountFrom + ` WHERE s.id=$1`
	var scan accountScanner
	var retired sql.NullTime
	if err := db.QueryRowContext(ctx, query, id).Scan(append(scan.destinations(), &retired)...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return goauth.SubjectLifecycleView{}, goauth.ErrAccountNotFound
		}
		return goauth.SubjectLifecycleView{}, fmt.Errorf("read subject lifecycle: %w", err)
	}
	view := goauth.SubjectLifecycleView{Account: scan.result()}
	if retired.Valid {
		view.RetiredAt = &retired.Time
	}
	return view, nil
}

// Canonical first lock for mutations that are legal on ordinary disabled
// accounts but must never attach authentication to a terminal subject.
func lockUnretiredSubject(ctx context.Context, tx *sql.Tx, id goauth.SubjectID) (int64, error) {
	var version int64
	var retired sql.NullTime
	err := tx.QueryRowContext(ctx, `
SELECT security_version,retired_at FROM auth_subjects WHERE id=$1 FOR UPDATE`, id).Scan(&version, &retired)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, goauth.ErrAccountNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("lock subject lifecycle: %w", err)
	}
	if retired.Valid {
		return 0, goauth.ErrSubjectRetired
	}
	return version, nil
}

func (s *Store) RetireLocalIdentity(
	ctx context.Context, request goauth.RetireLocalIdentityStoreRequest,
) (goauth.SubjectLifecycleView, error) {
	if request.SubjectID.IsZero() {
		return goauth.SubjectLifecycleView{}, goauth.ErrAccountNotFound
	}
	if err := validateLocalIdentifierScheme(request.Scheme); err != nil {
		return goauth.SubjectLifecycleView{}, err
	}
	if request.ExpectedSecurityVersion < 1 {
		return goauth.SubjectLifecycleView{}, goauth.ErrSecurityVersionMismatch
	}
	if !identifierbounds.Valid(request.ExpectedNormalizedValue) {
		return goauth.SubjectLifecycleView{}, goauth.ErrInvalidIdentifier
	}
	if request.Now.IsZero() {
		return goauth.SubjectLifecycleView{}, errors.New("retire local identity requires a timestamp")
	}
	started := time.Now()
	tx, owned, err := s.beginWrite(ctx)
	if err != nil {
		return goauth.SubjectLifecycleView{}, fmt.Errorf("begin subject retirement: %w", err)
	}
	defer rollbackWrite(tx, owned)
	version, err := lockUnretiredSubject(ctx, tx, request.SubjectID)
	if err != nil {
		return goauth.SubjectLifecycleView{}, err
	}
	if version != request.ExpectedSecurityVersion {
		return goauth.SubjectLifecycleView{}, goauth.ErrSecurityVersionMismatch
	}
	identifier, err := getLocalIdentifier(ctx, tx, request.SubjectID, request.Scheme, true)
	if err != nil {
		return goauth.SubjectLifecycleView{}, err
	}
	if identifier.NormalizedValue != request.ExpectedNormalizedValue {
		return goauth.SubjectLifecycleView{}, goauth.ErrLocalIdentifierConflict
	}
	var credentialSubject goauth.SubjectID
	err = tx.QueryRowContext(ctx, `
SELECT subject_id FROM auth_local_credentials WHERE subject_id=$1 FOR UPDATE`, request.SubjectID).Scan(&credentialSubject)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.SubjectLifecycleView{}, goauth.ErrAccountNotFound
	}
	if err != nil {
		return goauth.SubjectLifecycleView{}, fmt.Errorf("lock retirement credential: %w", err)
	}
	if version == math.MaxInt64 {
		return goauth.SubjectLifecycleView{}, errors.New("subject retirement security version overflow")
	}
	now := securityTime(ctx, request.Now, started)
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_subjects SET status='disabled',retired_at=$2,security_version=security_version+1,updated_at=$2
WHERE id=$1`, request.SubjectID, now); err != nil {
		return goauth.SubjectLifecycleView{}, fmt.Errorf("mark subject retired: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM auth_identifiers WHERE id=$1`, identifier.ID); err != nil {
		return goauth.SubjectLifecycleView{}, fmt.Errorf("release retired local identifier: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM auth_local_credentials WHERE subject_id=$1`, request.SubjectID); err != nil {
		return goauth.SubjectLifecycleView{}, fmt.Errorf("delete retired local credential: %w", err)
	}
	if _, err := revokeSubjectSecurityState(ctx, tx, request.SubjectID, now); err != nil {
		return goauth.SubjectLifecycleView{}, err
	}
	if err := invalidatePasswordResets(ctx, tx, request.SubjectID, now); err != nil {
		return goauth.SubjectLifecycleView{}, err
	}
	view, err := getSubjectLifecycle(ctx, tx, request.SubjectID)
	if err != nil {
		return goauth.SubjectLifecycleView{}, err
	}
	if err := finishWrite(tx, owned); err != nil {
		return goauth.SubjectLifecycleView{}, fmt.Errorf("commit subject retirement: %w", err)
	}
	return view, nil
}

var (
	_ goauth.SubjectLifecycleReader       = (*Store)(nil)
	_ goauth.LocalIdentityRetirementStore = (*Store)(nil)
)
