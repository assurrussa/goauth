package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	// Register the pgx database/sql driver used by DSN-backed Runtime construction.
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/assurrussa/goauth"
)

type Config struct {
	DB                 *sql.DB
	DSN                string
	AutoMigrate        bool
	ConnectionTimeout  time.Duration
	NotificationSender goauth.NotificationSender
	NotificationWorker NotificationWorkerConfig
	Runtime            goauth.Config
}

// Runtime owns a fully assembled goauth Runtime and, when constructed from a
// DSN, the database handle opened for it.
type Runtime struct {
	*goauth.Runtime
	db                  *sql.DB
	store               *Store
	oidcRefreshTokens   *OIDCRefreshTokenStore
	notificationSender  goauth.NotificationSender
	notificationWorker  NotificationWorkerConfig
	notificationNow     func() time.Time
	notificationRunning atomic.Bool
	ownsDB              bool
}

func NewRuntime(config Config) (*Runtime, error) {
	if err := validateRuntimeHooks(config); err != nil {
		return nil, err
	}
	if err := validateRuntimeIdentifierSchemes(config.Runtime.IdentifierResolvers); err != nil {
		return nil, err
	}
	worker, err := config.NotificationWorker.withDefaults()
	if err != nil {
		return nil, err
	}
	if config.Runtime.Now == nil {
		config.Runtime.Now = time.Now
	}

	db := config.DB
	ownsDB := false
	if db == nil {
		if strings.TrimSpace(config.DSN) == "" {
			return nil, errors.New("PostgreSQL DB or DSN is required")
		}
		var err error
		db, err = sql.Open("pgx", strings.TrimSpace(config.DSN))
		if err != nil {
			return nil, fmt.Errorf("open PostgreSQL database: %w", err)
		}
		ownsDB = true
	}
	closeOnError := func() {
		if ownsDB {
			_ = db.Close()
		}
	}
	connectionTimeout := config.ConnectionTimeout
	if connectionTimeout <= 0 {
		connectionTimeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		closeOnError()
		return nil, fmt.Errorf("ping PostgreSQL database: %w", err)
	}
	store, err := NewStore(db)
	if err != nil {
		closeOnError()
		return nil, err
	}
	config.Runtime.Store = store
	config.Runtime.AuthTransaction = store
	if config.NotificationSender != nil {
		config.Runtime.EventSink = store
		config.Runtime.AuditSink = store
		config.Runtime.ManagedNotificationDelivery = true
	} else {
		config.Runtime.AuditSink = store
	}
	coreRuntime, err := goauth.NewRuntime(config.Runtime)
	if err != nil {
		closeOnError()
		return nil, fmt.Errorf("assemble goauth Runtime: %w", err)
	}
	oidcRefreshTokens, err := NewOIDCRefreshTokenStore(db, config.Runtime.TokenHMACKeys)
	if err != nil {
		closeOnError()
		return nil, fmt.Errorf("assemble OIDC refresh token store: %w", err)
	}
	if config.AutoMigrate {
		if err := Migrate(ctx, db); err != nil {
			closeOnError()
			return nil, err
		}
	} else if err := VerifySchema(ctx, db); err != nil {
		closeOnError()
		return nil, fmt.Errorf("verify goauth PostgreSQL schema: %w", err)
	}

	return &Runtime{
		Runtime:            coreRuntime,
		db:                 db,
		store:              store,
		oidcRefreshTokens:  oidcRefreshTokens,
		notificationSender: config.NotificationSender,
		notificationWorker: worker,
		notificationNow:    config.Runtime.Now,
		ownsDB:             ownsDB,
	}, nil
}

// OIDCRefreshTokens returns the digest-only PostgreSQL adapter used by an
// optional OIDC provider.
func (r *Runtime) OIDCRefreshTokens() *OIDCRefreshTokenStore {
	if r == nil {
		return nil
	}

	return r.oidcRefreshTokens
}

// Resolve implements the OIDC claims resolver using the canonical Account.
func (r *Runtime) Resolve(ctx context.Context, subjectID string) (goauth.Account, error) {
	if r == nil || r.store == nil {
		return goauth.Account{}, errors.New("PostgreSQL Runtime is not initialized")
	}
	parsed, err := goauth.ParseSubjectID(subjectID)
	if err != nil {
		return goauth.Account{}, goauth.ErrAccountNotFound
	}

	return r.store.GetAccount(ctx, parsed)
}

func (r *Runtime) Close() error {
	if r == nil || !r.ownsDB || r.db == nil {
		return nil
	}

	return r.db.Close()
}

func validateRuntimeHooks(config Config) error {
	if config.Runtime.NotificationDelivery == goauth.NotificationDeliveryDisabled && config.NotificationSender != nil {
		return errors.New("disabled notification delivery cannot configure NotificationSender")
	}
	if config.Runtime.AuditSink != nil {
		return errors.New("PostgreSQL requires its local audit store; " +
			"use direct root Runtime for custom transactional audit wiring")
	}
	if config.Runtime.AuthTransaction != nil {
		return errors.New("PostgreSQL assembles AuthTransaction; use direct root Runtime for custom transaction wiring")
	}
	if config.Runtime.EventSink != nil {
		return errors.New("PostgreSQL requires its local encrypted notification queue; " +
			"use direct root Runtime for custom transactional event wiring")
	}
	if config.NotificationSender != nil && (config.Runtime.EventSink != nil ||
		config.Runtime.NotificationRenderer != nil || config.Runtime.AuditSink != nil ||
		config.Runtime.NotificationTransaction != nil || config.Runtime.ManagedNotificationDelivery) {
		return errors.New("managed NotificationSender cannot be combined with custom event, renderer, audit, or transaction hooks")
	}
	if config.NotificationSender == nil && (config.Runtime.NotificationTransaction != nil ||
		config.Runtime.ManagedNotificationDelivery) {
		return errors.New("PostgreSQL notification transactions require a managed NotificationSender; " +
			"use direct root Runtime assembly for custom transaction wiring")
	}
	return nil
}
