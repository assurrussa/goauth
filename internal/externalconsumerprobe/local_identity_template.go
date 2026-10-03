package externalconsumerprobe

const localIdentityProbeTest = `
func TestEmailLessIdentityExternalConsumer(t *testing.T) {
	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.IdentifierResolvers = map[goauth.IdentifierScheme]goauth.IdentifierResolver{
			"probe_login": goauth.IdentifierResolverFunc(func(
				_ context.Context, input goauth.IdentifierInput,
			) (goauth.IdentifierInput, error) {
				return input, nil
			}),
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	identifier := goauth.IdentifierInput{Scheme: "probe_login", Value: "local-probe"}
	account, err := fixture.Runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
		Identifier: identifier, Password: "Local-Identity-Probe-Passphrase-42",
	})
	if err != nil {
		t.Fatal(err)
	}
	if account.PrimaryEmail.ID != "" || account.EmailVerified() {
		t.Fatal("provisioning fabricated email")
	}
	verified, err := fixture.Runtime.VerifyCredential(t.Context(), goauth.Credential{
		Identifier: identifier, Password: "Local-Identity-Probe-Passphrase-42",
	})
	if err != nil || verified.Subject.ID != account.Subject.ID {
		t.Fatalf("verify local identity: %v", err)
	}
	hasher, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{})
	if err != nil {
		t.Fatal(err)
	}
	phc, err := hasher.HashPassword("Imported-Identity-Probe-Passphrase-42")
	if err != nil {
		t.Fatal(err)
	}
	request := goauth.ImportLocalIdentityRequest{SubjectID: goauth.NewSubjectID(),
		Identifier:  goauth.IdentifierInput{Scheme: "probe_login", Value: "imported-probe"},
		PasswordPHC: phc, PasswordInputPolicy: goauth.PasswordInputPolicyUnicode, Status: goauth.SubjectStatusDisabled}
	imported, err := fixture.Runtime.ImportLocalIdentity(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if imported.Subject.ID != request.SubjectID || imported.Subject.Status != goauth.SubjectStatusDisabled {
		t.Fatal("import lost canonical identity or status")
	}
	if _, err := fixture.Runtime.ImportLocalIdentity(t.Context(), request); !errors.Is(err, goauth.ErrIdentifierAlreadyExists) {
		t.Fatalf("import merged existing identity: %v", err)
	}
}
`

const localIdentityPostgresProbeTest = `
func TestEmailLessManagedImportExternalConsumer(t *testing.T) {
	runtime := newHostProbeRuntime(t, true)
	projection := hostProbeProjection(t, runtime.Database())
	hasher, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{})
	if err != nil {
		t.Fatal(err)
	}
	phc, err := hasher.HashPassword(hostProbePassword)
	if err != nil {
		t.Fatal(err)
	}
	request := goauth.ImportLocalIdentityRequest{SubjectID: goauth.NewSubjectID(),
		Identifier:  goauth.IdentifierInput{Scheme: "probe_login", Value: "import-" + goauth.NewSubjectID().String()},
		PasswordPHC: phc, PasswordInputPolicy: goauth.PasswordInputPolicyUnicode, Status: goauth.SubjectStatusActive}
	cleanupHostProbeSubject(t, runtime.Database(), request.SubjectID)
	stop := errors.New("host mapping failure")
	for _, rollback := range []bool{true, false} {
		err = runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
			account, err := runtime.ImportLocalIdentity(ctx, request)
			if err != nil {
				return err
			}
			executor, err := runtime.SQLExecutor(ctx)
			if err != nil {
				return err
			}
			if _, err := executor.ExecContext(ctx,
				"INSERT INTO "+projection+" (subject_id, selector) VALUES ($1,$2)",
				account.Subject.ID, request.Identifier.Value,
			); err != nil {
				return err
			}
			if rollback {
				return stop
			}
			return nil
		})
		if rollback {
			if !errors.Is(err, stop) {
				t.Fatalf("unexpected rollback: %v", err)
			}
			if _, err := runtime.GetAccount(t.Context(), request.SubjectID); !errors.Is(err, goauth.ErrAccountNotFound) {
				t.Fatalf("import escaped rollback: %v", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
	proof, err := runtime.PrepareCredential(t.Context(), goauth.Credential{
		Identifier: request.Identifier, Password: hostProbePassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		account, err := runtime.RevalidateCredential(ctx, proof)
		if err != nil {
			return err
		}
		if account.Subject.ID != request.SubjectID || account.PrimaryEmail.ID != "" || account.EmailVerified() {
			return errors.New("incorrect canonical identity")
		}
		executor, err := runtime.SQLExecutor(ctx)
		if err != nil {
			return err
		}
		var mapped goauth.SubjectID
		if err := executor.QueryRowContext(ctx,
			"SELECT subject_id FROM "+projection+" WHERE selector=$1", request.Identifier.Value).Scan(&mapped); err != nil {
			return err
		}
		if mapped != account.Subject.ID {
			return errors.New("host mapping used a different subject")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
`
