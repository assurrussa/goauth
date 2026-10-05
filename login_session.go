package goauth

import "context"

// issueLoginSession preserves the password-verified security snapshot. Only an
// email verification of that same identity may refresh preparation, once.
func (r *Runtime) issueLoginSession(
	ctx context.Context, account Account, realm Realm, scope SessionScope,
) (LoginResult, error) {
	for attempt := range 2 {
		prepared, err := r.prepareSession(ctx, account, realm, scope)
		if err != nil {
			return LoginResult{}, err
		}
		var verified Account
		err = r.authTransaction.InAuthTransaction(ctx, func(ctx context.Context) error {
			current, err := r.lockActiveAccount(ctx, account.Subject.ID)
			if err != nil {
				return err
			}
			if current.Subject.ID != account.Subject.ID ||
				current.Subject.SecurityVersion != account.Subject.SecurityVersion ||
				current.PrimaryEmail.ID != account.PrimaryEmail.ID ||
				current.PrimaryEmail.SubjectID != account.PrimaryEmail.SubjectID ||
				current.PrimaryEmail.Scheme != account.PrimaryEmail.Scheme ||
				current.PrimaryEmail.NormalizedValue != account.PrimaryEmail.NormalizedValue {
				return ErrSecurityVersionMismatch
			}
			if current.EmailVerified() != account.EmailVerified() {
				if attempt != 0 || realm != RealmUser || account.EmailVerified() {
					return ErrSecurityVersionMismatch
				}
				verified = current
				// Commit only this read-only admission before running hooks and
				// signing again. Never alter the scope of an already signed pair.
				return nil
			}
			return r.createPreparedSession(ctx, prepared)
		})
		if err != nil {
			return LoginResult{}, err
		}
		if verified.IsZero() {
			return LoginResult{Account: account, Tokens: prepared.tokens}, nil
		}
		account = verified
		scope = SessionScopeAuthenticated
	}
	return LoginResult{}, ErrSecurityVersionMismatch
}
