//go:build integration

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

// This explicit gate uses only public packages, the runnable example and its
// own disposable database. Invoking it without a browser engine fails.
func TestPostgresBrowserAcceptance(t *testing.T) {
	if os.Getenv("GOAUTH_BROWSER_ACCEPTANCE") != "1" {
		t.Skip("explicit browser acceptance required")
	}
	fixtureDir := os.Getenv("GOAUTH_BROWSER_FIXTURE_DIR")
	tlsConfig, fixtureExpiresAt, err := browserTLSConfig(fixtureDir, time.Now())
	require.NoError(t, err, "explicit synthetic TLS fixture and separately approved disposable browser profile required")
	require.NotEqual(t, "0", os.Getenv("NODE_TLS_REJECT_UNAUTHORIZED"), "TLS verification cannot be disabled")
	dsn := os.Getenv("GOAUTH_TEST_POSTGRES_DSN")
	require.NotEmpty(t, dsn, "explicit disposable PostgreSQL fixture DSN required")
	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", parsed.Hostname(), "only local disposable fixture is permitted")
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Second)
	defer cancel()
	deadline, ok := ctx.Deadline()
	require.True(t, ok)
	require.NoError(t, browserFixtureCoversDeadline(fixtureExpiresAt, deadline))
	adminDB, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	defer adminDB.Close()
	databaseName := "goauth_browser_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = adminDB.ExecContext(ctx, `CREATE DATABASE `+databaseName)
	require.NoError(t, err)
	defer func() {
		_, dropErr := adminDB.ExecContext(context.Background(), `DROP DATABASE `+databaseName+` WITH (FORCE)`)
		require.NoError(t, dropErr)
	}()
	scoped := *parsed
	scoped.Path = "/" + databaseName
	db, err := sql.Open("pgx", scoped.String())
	require.NoError(t, err)
	defer db.Close()
	server := httptest.NewUnstartedServer(nil)
	server.TLS = tlsConfig
	origin := "https://localhost:" + strings.Split(server.Listener.Addr().String(), ":")[1]
	keys := func(id string, value byte) goauth.KeyRing {
		ring, keyErr := goauth.NewKeyRing(id, goauth.Key{ID: id, Material: []byte(strings.Repeat(string(value), 32))})
		require.NoError(t, keyErr)
		return ring
	}
	var mutex sync.Mutex
	deliveries := []goauth.NotificationDelivery{}
	var encrypted, submitted atomic.Int64
	runtime, err := postgres.NewRuntime(postgres.Config{DB: db, AutoMigrate: true, NotificationSender: goauth.NotificationSenderFunc(func(sendCtx context.Context, delivery goauth.NotificationDelivery) error {
		var rows int
		if queryErr := db.QueryRowContext(sendCtx, `SELECT count(*) FROM auth_notification_deliveries WHERE id=$1 AND octet_length(ciphertext)>0`, delivery.ID).Scan(&rows); queryErr != nil {
			return queryErr
		}
		if rows == 1 {
			encrypted.Add(1)
		}
		mutex.Lock()
		deliveries = append(deliveries, delivery)
		mutex.Unlock()
		return nil
	}), Runtime: goauth.Config{Signing: goauth.SigningConfig{Issuer: origin, Audience: "nethttp-browser-acceptance", Keys: keys("jwt", 1)}, TokenHMACKeys: keys("token", 2), OutboxAEADKeys: keys("envelope", 3), AccessTTL: 35 * time.Second, ResetResponseFloor: time.Nanosecond, URLBuilder: goauth.URLBuilderFunc(func(_ context.Context, token string) (string, error) {
		return origin + "/#reset=" + url.QueryEscape(token), nil
	})}})
	require.NoError(t, err)
	defer func() { require.NoError(t, runtime.Close()) }()
	workerCtx, stopWorker := context.WithCancel(ctx)
	workerDone := make(chan error, 1)
	go func() { workerDone <- runtime.RunNotifications(workerCtx) }()
	defer func() { stopWorker(); <-workerDone }()
	handler, err := newHandler(runtime, true)
	require.NoError(t, err)
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fixture/delivery":
			mutex.Lock()
			defer mutex.Unlock()
			for _, delivery := range deliveries {
				if delivery.Notification.To == r.URL.Query().Get("to") && delivery.Notification.Template == r.URL.Query().Get("template") {
					_ = json.NewEncoder(w).Encode(delivery.Notification)
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
			return
		case "/fixture/stats":
			_ = json.NewEncoder(w).Encode(map[string]int64{"encrypted": encrypted.Load(), "submitted": submitted.Load()})
			return
		}
		if r.URL.Path == "/browser/refresh" {
			submitted.Add(1)
		}
		handler.ServeHTTP(w, r)
	})
	server.StartTLS()
	defer server.Close()
	scriptPath, err := filepath.Abs("browser-acceptance.mjs")
	require.NoError(t, err)
	command := exec.CommandContext(ctx, "node", scriptPath, origin) //nolint:gosec // fixed local acceptance script and ephemeral listener
	// Route.fetch uses Playwright's Node-side HTTPS client, so it needs the same
	// explicit fixture CA as raw requests. This affects this child process only.
	command.Env = append(os.Environ(), "NODE_EXTRA_CA_CERTS="+filepath.Join(fixtureDir, "ca.pem"), "NODE_OPTIONS=")
	output, err := command.CombinedOutput()
	require.NoError(t, err, string(output))
	require.True(t, time.Now().Before(fixtureExpiresAt), "fixture validity expired before accepting the browser result")
	t.Log(string(output))
	require.GreaterOrEqual(t, encrypted.Load(), int64(3), "worker must deliver encrypted confirmation, reset and email-change rows")
}
