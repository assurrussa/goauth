package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	// Register the pgx database/sql driver used by DSN-backed Runtime construction.
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/assurrussa/goauth"
)

type Config struct {
	DB                *sql.DB
	DSN               string
	AutoMigrate       bool
	ConnectionTimeout time.Duration
	Runtime           goauth.Config
}

// Runtime owns a fully assembled goauth Runtime and, when constructed from a
// DSN, the database handle opened for it.
type Runtime struct {
	*goauth.Runtime
	db                *sql.DB
	store             *Store
	oidcRefreshTokens *OIDCRefreshTokenStore
	ownsDB            bool
}

func NewRuntime(config Config) (*Runtime, error) {
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
	if config.AutoMigrate {
		if err := Migrate(ctx, db); err != nil {
			closeOnError()
			return nil, err
		}
	}
	store, err := NewStore(db)
	if err != nil {
		closeOnError()
		return nil, err
	}
	config.Runtime.Store = store
	if config.Runtime.AuditSink == nil {
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

	return &Runtime{
		Runtime:           coreRuntime,
		db:                db,
		store:             store,
		oidcRefreshTokens: oidcRefreshTokens,
		ownsDB:            ownsDB,
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
