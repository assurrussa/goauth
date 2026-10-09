package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

// These are host tables, not a second credential authority. All references use
// the immutable canonical subject ID; the custom login is never a membership key.
const hostSchema = `
CREATE TABLE IF NOT EXISTS example_host_memberships (
    subject_id uuid NOT NULL REFERENCES auth_subjects(id),
    project_id text NOT NULL,
    active boolean NOT NULL DEFAULT true,
    PRIMARY KEY (subject_id, project_id)
);
CREATE TABLE IF NOT EXISTS example_host_sessions (
    token_digest bytea PRIMARY KEY,
    subject_id uuid NOT NULL REFERENCES auth_subjects(id),
    project_id text NOT NULL,
    security_version bigint NOT NULL,
    expires_at timestamptz NOT NULL
);`

var errDenied = errors.New("host session denied")

type sessionHost struct{ auth *postgres.Runtime }

func (h sessionHost) login(ctx context.Context, credential goauth.Credential, project string) (string, error) {
	// Rate admission and expensive password work happen before holding DB locks.
	proof, err := h.auth.PrepareCredential(ctx, credential)
	if err != nil {
		return "", err
	}
	return h.finishLogin(ctx, proof, project)
}

func (h sessionHost) finishLogin(ctx context.Context, proof *postgres.CredentialProof, project string) (string, error) {
	token, err := randomSecret()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(token))
	err = h.auth.InOwnedAuthTransaction(ctx, func(txctx context.Context) error {
		// Canonical subject lock first, then membership. Every security/membership
		// mutation in a real host must use this same lock order.
		account, err := h.auth.RevalidateCredential(txctx, proof)
		if err != nil {
			return err
		}
		q, err := h.auth.SQLExecutor(txctx)
		if err != nil {
			return err
		}
		if err := requireMembership(txctx, q, account.Subject.ID, project); err != nil {
			return err
		}
		_, err = q.ExecContext(txctx, `INSERT INTO example_host_sessions
            (token_digest, subject_id, project_id, security_version, expires_at)
            VALUES ($1, $2, $3, $4, $5)`, digest[:], account.Subject.ID, project,
			account.Subject.SecurityVersion, time.Now().Add(15*time.Minute))
		return err
	})
	if err != nil {
		// Includes unknown commit outcome: no token or success escapes; no retry.
		return "", err
	}
	return token, nil
}

func requireMembership(ctx context.Context, q postgres.SQLExecutor, subject goauth.SubjectID, project string) error {
	var active bool
	err := q.QueryRowContext(ctx, `SELECT active FROM example_host_memberships
        WHERE subject_id=$1 AND project_id=$2 FOR UPDATE`, subject, project).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) || err == nil && !active {
		return errDenied
	}
	return err
}

func (h sessionHost) authenticate(ctx context.Context, token, project string) (goauth.Account, error) {
	if len(token) != 43 {
		return goauth.Account{}, errDenied
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != 32 {
		return goauth.Account{}, errDenied
	}
	digest := sha256.Sum256([]byte(token))
	var account goauth.Account
	err = h.auth.InOwnedAuthTransaction(ctx, func(txctx context.Context) error {
		q, err := h.auth.SQLExecutor(txctx)
		if err != nil {
			return err
		}
		var subject goauth.SubjectID
		var version int64
		var expires time.Time
		err = q.QueryRowContext(txctx, `SELECT subject_id, security_version, expires_at
            FROM example_host_sessions WHERE token_digest=$1 AND project_id=$2`, digest[:], project).
			Scan(&subject, &version, &expires)
		if errors.Is(err, sql.ErrNoRows) {
			return errDenied
		}
		if err != nil {
			return err
		}
		// Host sessions are not goauth sessions: canonical invalidation does not
		// delete these rows. Recheck status/version on EVERY authenticated use.
		if err := q.QueryRowContext(txctx, `SELECT id FROM auth_subjects WHERE id=$1 FOR UPDATE`, subject).Scan(&subject); err != nil {
			return err
		}
		account, err = h.auth.GetAccount(txctx, subject)
		if err != nil {
			return err
		}
		if account.Subject.Status != goauth.SubjectStatusActive || account.Subject.SecurityVersion != version {
			return errDenied
		}
		if err := requireMembership(txctx, q, subject, project); err != nil {
			return err
		}
		if !time.Now().Before(expires) {
			return errDenied
		}
		// Protected host DB writes belong HERE through q, under the same locks.
		// The returned account is an identity snapshot, not a lasting permission.
		return nil
	})
	if err != nil {
		return goauth.Account{}, err
	}
	return account, nil
}
