package externalconsumerprobe

const managedHostProbeTest = `
const hostProbePassword = "Probe-Host-Passphrase-123"

func newHostProbeRuntime(t *testing.T, disabled bool) *postgres.Runtime {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("GOAUTH_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Fatal("GOAUTH_TEST_POSTGRES_DSN is required for the PostgreSQL external consumer probe")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	keyRing := func(name string, fill byte) goauth.KeyRing {
		ring, err := goauth.NewKeyRing(name, goauth.Key{ID: name, Material: bytes.Repeat([]byte{fill}, 32)})
		if err != nil {
			t.Fatal(err)
		}
		return ring
	}
	config := postgres.Config{DB: db, AutoMigrate: true, Runtime: goauth.Config{
		Signing: goauth.SigningConfig{
			Issuer: "https://auth.example.test", Audience: "host-probe", Keys: keyRing("host-jwt", 1),
		},
		TokenHMACKeys: keyRing("host-token", 2), ResetResponseFloor: time.Nanosecond,
  IdentifierResolvers: map[goauth.IdentifierScheme]goauth.IdentifierResolver{
   "probe_login": goauth.IdentifierResolverFunc(func(
 _ context.Context, input goauth.IdentifierInput,
 ) (goauth.IdentifierInput, error) { return input, nil }),
  },
	}}
	if disabled {
		config.Runtime.NotificationDelivery = goauth.NotificationDeliveryDisabled
	} else {
		config.Runtime.OutboxAEADKeys = keyRing("host-envelope", 3)
		config.Runtime.URLBuilder = goauth.URLBuilderFunc(func(_ context.Context, token string) (string, error) {
			return "https://app.example.test/reset?token=" + url.QueryEscape(token), nil
		})
		// This probe asserts enqueue atomicity and never starts the delivery worker.
		config.NotificationSender = goauth.NotificationSenderFunc(func(context.Context, goauth.NotificationDelivery) error {
			return errors.New("host transaction probe must not deliver notifications")
		})
	}
	runtime, err := postgres.NewRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := runtime.Close(); err != nil {
			t.Errorf("close host probe runtime: %v", err)
		}
	})
	if runtime.Database() != db {
		t.Fatal("runtime did not retain the exact shared database handle")
	}
	return runtime
}

func hostProbeProjection(t *testing.T, db *sql.DB) string {
	t.Helper()
	name := "goauth_host_probe_" + strings.ReplaceAll(goauth.NewSubjectID().String(), "-", "")
	if _, err := db.ExecContext(t.Context(), "CREATE TABLE "+name+" (subject_id uuid PRIMARY KEY, selector text)"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := db.ExecContext(context.Background(), "DROP TABLE "+name); err != nil {
			t.Errorf("drop host projection: %v", err)
		}
	})
	return name
}

func cleanupHostProbeSubject(t *testing.T, db *sql.DB, subject goauth.SubjectID) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := db.ExecContext(ctx, "DELETE FROM auth_security_audit_events WHERE subject_id=$1", subject); err != nil {
			t.Errorf("clean host audit: %v", err)
		}
		if _, err := db.ExecContext(ctx, "DELETE FROM auth_subjects WHERE id=$1", subject); err != nil {
			t.Errorf("clean host subject: %v", err)
		}
	})
}

func provisionHostProbe(t *testing.T, runtime *postgres.Runtime) goauth.Account {
	t.Helper()
	account, err := runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email:    "host-" + strings.ReplaceAll(goauth.NewSubjectID().String(), "-", "") + "@example.test",
		Password: hostProbePassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	cleanupHostProbeSubject(t, runtime.Database(), account.Subject.ID)
	return account
}

func hostProbeCount(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var count int
	if err := db.QueryRowContext(t.Context(), query, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestManagedHostTransactionExternalConsumer(t *testing.T) {
	runtime := newHostProbeRuntime(t, true)
	foreign := newHostProbeRuntime(t, true)
	projection := hostProbeProjection(t, runtime.Database())
	rejection := errors.New("host projection rejected")
	permissions, err := runtime.RBAC(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, abort := range []bool{true, false} {
		var subject goauth.SubjectID
		var roleID int64
		err := runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
			account, err := runtime.ProvisionTrustedLocalAccount(ctx, goauth.RegisterRequest{
				Email:    "atomic-" + strings.ReplaceAll(goauth.NewSubjectID().String(), "-", "") + "@example.test",
				Password: hostProbePassword,
			})
			if err != nil {
				return err
			}
			subject = account.Subject.ID
			executor, err := runtime.SQLExecutor(ctx)
			if err != nil {
				return err
			}
			if _, exposed := executor.(interface{ Commit() error }); exposed {
				return errors.New("executor exposes commit ownership")
			}
			if _, exposed := executor.(interface{ Rollback() error }); exposed {
				return errors.New("executor exposes rollback ownership")
			}
			if _, exposed := executor.(*sql.Tx); exposed {
				return errors.New("executor exposes raw transaction")
			}
			if _, err := foreign.SQLExecutor(ctx); err == nil {
				return errors.New("foreign database accepted managed context")
			}
			if err := foreign.InAuthTransaction(ctx, func(context.Context) error { return nil }); err == nil {
				return errors.New("foreign database joined another handle's transaction")
			}
			if _, err := executor.ExecContext(ctx, "INSERT INTO "+projection+"(subject_id) VALUES($1)", subject); err != nil {
				return err
			}
			if err := runtime.InAuthTransaction(ctx, func(nested context.Context) error {
				_, err := runtime.UpdateBasicProfile(nested, subject, goauth.BasicProfile{DisplayName: "Nested host profile"})
				return err
			}); err != nil {
				return err
			}
			// A nested success cannot commit either canonical or host state before its owner.
			if hostProbeCount(t, runtime.Database(),
				"SELECT count(*) FROM auth_subjects WHERE id=$1",
				subject,
			) != 0 {
				return errors.New("nested transaction committed early")
			}
			if _, err := runtime.LogoutAll(ctx, subject); err != nil {
				return err
			}
			role, err := permissions.UpsertRole(ctx, rbac.Role{
				Slug: "host-role-" + strings.ReplaceAll(goauth.NewSubjectID().String(), "-", ""), Name: "Host transaction probe",
			})
			if err != nil {
				return err
			}
			roleID = role.ID
			if err := permissions.AssignRole(ctx, subject, role.Slug); err != nil {
				return err
			}
			if abort {
				return rejection
			}
			return nil
		})
		t.Cleanup(func() {
			_, _ = runtime.Database().ExecContext(context.Background(), "DELETE FROM auth_roles WHERE id=$1", roleID)
		})
		cleanupHostProbeSubject(t, runtime.Database(), subject)
		subjects := hostProbeCount(t, runtime.Database(),
			"SELECT count(*) FROM auth_subjects WHERE id=$1",
			subject,
		)
		projections := hostProbeCount(t, runtime.Database(), "SELECT count(*) FROM "+projection+" WHERE subject_id=$1", subject)
		audits := hostProbeCount(t, runtime.Database(),
			"SELECT count(*) FROM auth_security_audit_events WHERE subject_id=$1",
			subject,
		)
		roles := hostProbeCount(t, runtime.Database(),
			"SELECT count(*) FROM auth_subject_roles WHERE subject_id=$1",
			subject,
		)
		if abort {
			if !errors.Is(err, rejection) || subjects != 0 || projections != 0 || audits != 0 || roles != 0 {
				t.Fatal("failed host transaction leaked canonical, audit or projection state")
			}
		} else {
			if err != nil || subjects != 1 || projections != 1 || audits == 0 || roles != 1 {
				t.Fatalf(
					"host transaction did not commit together: subjects=%d projection=%d audits=%d roles=%d err=%v",
					subjects, projections, audits, roles, err,
				)
			}
			account, err := runtime.GetAccount(t.Context(), subject)
			if err != nil || account.Profile.DisplayName != "Nested host profile" {
				t.Fatalf("nested profile not committed: %v", err)
			}
		}
	}
	executor, err := runtime.SQLExecutor(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := executor.QueryContext(t.Context(), "SELECT subject_id FROM "+projection)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("executor outside managed context did not query committed host state")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialProofExternalConsumer(t *testing.T) {
	runtime := newHostProbeRuntime(t, true)
	account := provisionHostProbe(t, runtime)
	credential := goauth.Credential{Identifier: goauth.IdentifierInput{
		Scheme: goauth.IdentifierSchemeEmail, Value: account.PrimaryEmail.DisplayValue,
	}, Password: hostProbePassword}
	proof, err := runtime.PrepareCredential(t.Context(), credential)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.RevalidateCredential(t.Context(), proof); err == nil {
		t.Fatal("credential proof revalidated without managed owner")
	}
	err = runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		verified, err := runtime.RevalidateCredential(ctx, proof)
		if err != nil {
			return err
		}
		if verified.Subject.ID != account.Subject.ID {
			return errors.New("proof revalidated a different canonical subject")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.LogoutAll(t.Context(), account.Subject.ID); err != nil {
		t.Fatal(err)
	}
	err = runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		_, err := runtime.RevalidateCredential(ctx, proof)
		return err
	})
	if !errors.Is(err, goauth.ErrInvalidCredentials) {
		t.Fatalf("stale security-version proof authorized membership: %v", err)
	}
}

func TestPasswordResetReceiptExternalConsumer(t *testing.T) {
	runtime := newHostProbeRuntime(t, false)
	account := provisionHostProbe(t, runtime)
	projection := hostProbeProjection(t, runtime.Database())
	rejection := errors.New("reset host association rejected")
	for _, abort := range []bool{true, false} {
		var receipt goauth.PasswordResetReceipt
		err := runtime.RequestPasswordResetWithReceipt(t.Context(), account.PrimaryEmail.DisplayValue,
			func(ctx context.Context, value goauth.PasswordResetReceipt) error {
				receipt = value
				if value.SubjectID != account.Subject.ID || value.Selector == "" {
					return errors.New("reset receipt lost public correlation")
				}
				executor, err := runtime.SQLExecutor(ctx)
				if err != nil {
					return err
				}
				if _, err := executor.ExecContext(ctx,
					"INSERT INTO "+projection+"(subject_id,selector) VALUES($1,$2)",
					value.SubjectID, value.Selector,
				); err != nil {
					return err
				}
				if abort {
					return rejection
				}
				return nil
			})
		resets := hostProbeCount(t, runtime.Database(),
			"SELECT count(*) FROM auth_password_reset_records WHERE subject_id=$1 AND selector=$2",
			account.Subject.ID, receipt.Selector,
		)
		queued := hostProbeCount(t, runtime.Database(),
			"SELECT count(*) FROM auth_notification_deliveries WHERE subject_id=$1 AND reference_id=$2",
			account.Subject.ID, receipt.Selector,
		)
		audits := hostProbeCount(t, runtime.Database(),
			"SELECT count(*) FROM auth_security_audit_events WHERE subject_id=$1 AND event_type='password_reset.issued'",
			account.Subject.ID,
		)
		projections := hostProbeCount(t, runtime.Database(),
			"SELECT count(*) FROM "+projection+" WHERE subject_id=$1 AND selector=$2",
			account.Subject.ID, receipt.Selector,
		)
		if abort {
			if !errors.Is(err, rejection) || resets != 0 || queued != 0 || audits != 0 || projections != 0 {
				t.Fatal("receipt callback failure leaked reset, enqueue, audit or projection")
			}
		} else {
			if err != nil || resets != 1 || queued != 1 || audits != 1 || projections != 1 {
				t.Fatalf("reset receipt writes did not commit together: %v", err)
			}
		}
	}
	called := false
	err := runtime.RequestPasswordResetWithReceipt(t.Context(), "absent-"+goauth.NewSubjectID().String()+"@example.test",
		func(context.Context, goauth.PasswordResetReceipt) error { called = true; return nil })
	if err != nil || called {
		t.Fatalf("suppressed reset invoked receipt callback: called=%v err=%v", called, err)
	}
}

func TestDisabledDeliveryPostgresExternalConsumer(t *testing.T) {
	runtime := newHostProbeRuntime(t, true)
	account := provisionHostProbe(t, runtime)
	before := hostProbeCount(t, runtime.Database(),
		"SELECT count(*) FROM auth_security_audit_events WHERE subject_id=$1",
		account.Subject.ID,
	)
	called := false
	err := runtime.RequestPasswordResetWithReceipt(t.Context(), account.PrimaryEmail.DisplayValue,
		func(context.Context, goauth.PasswordResetReceipt) error { called = true; return nil })
	if !errors.Is(err, goauth.ErrNotificationDeliveryDisabled) || called {
		t.Fatalf("disabled reset issuance: %v", err)
	}
	if err := runtime.SendEmailChallenge(
		t.Context(), account.Subject.ID, goauth.EmailChallengePurposeVerification,
	); !errors.Is(err, goauth.ErrNotificationDeliveryDisabled) {
		t.Fatalf("disabled challenge issuance: %v", err)
	}
	if err := runtime.ResetPassword(
		t.Context(), "old-token", "Probe-Replacement-Passphrase-456",
	); !errors.Is(err, goauth.ErrNotificationDeliveryDisabled) {
		t.Fatalf("disabled reset consumption: %v", err)
	}
	unchanged, err := runtime.GetAccount(t.Context(), account.Subject.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Subject.SecurityVersion != account.Subject.SecurityVersion ||
		hostProbeCount(t, runtime.Database(),
			"SELECT count(*) FROM auth_security_audit_events WHERE subject_id=$1",
			account.Subject.ID,
		) != before ||
		hostProbeCount(t, runtime.Database(),
			"SELECT count(*) FROM auth_email_challenges WHERE subject_id=$1",
			account.Subject.ID,
		) != 0 {
		t.Fatal("disabled commands mutated canonical, audit or challenge state")
	}
	_, err = runtime.ChangePassword(t.Context(), goauth.ChangePasswordRequest{
		SubjectID: account.Subject.ID, CurrentPassword: hostProbePassword, NewPassword: "Probe-Disabled-New-Passphrase-456",
	})
	if err != nil {
		t.Fatal(err)
	}
	if hostProbeCount(t, runtime.Database(),
		"SELECT count(*) FROM auth_password_reset_records WHERE subject_id=$1",
		account.Subject.ID,
	) != 0 ||
		hostProbeCount(t, runtime.Database(),
			"SELECT count(*) FROM auth_notification_deliveries WHERE subject_id=$1",
			account.Subject.ID,
		) != 0 {
		t.Fatal("disabled runtime persisted reset or notification state")
	}
	after := hostProbeCount(t, runtime.Database(),
		"SELECT count(*) FROM auth_security_audit_events WHERE subject_id=$1",
		account.Subject.ID,
	)
	if after <= before {
		t.Fatal("disabled password change lost mandatory audit")
	}
	executor, err := runtime.SQLExecutor(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var version int64
	if err := executor.QueryRowContext(t.Context(),
		"SELECT security_version FROM auth_subjects WHERE id=$1", account.Subject.ID,
	).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version <= account.Subject.SecurityVersion {
		t.Fatal("disabled password change lost canonical security mutation")
	}
}
`
