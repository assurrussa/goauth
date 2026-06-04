package legacysession

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/stretchr/testify/require"
)

type sessionPayload struct {
	ID    int64
	Email string
}

type testStorage struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newTestStorage() *testStorage {
	return &testStorage{data: make(map[string][]byte)}
}

func (s *testStorage) GetWithContext(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	value := append([]byte(nil), s.data[key]...)
	if len(value) == 0 {
		return nil, nil
	}

	return value, nil
}

func (s *testStorage) Get(key string) ([]byte, error) {
	return s.GetWithContext(context.Background(), key)
}

func (s *testStorage) SetWithContext(_ context.Context, key string, value []byte, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = append([]byte(nil), value...)
	return nil
}

func (s *testStorage) Set(key string, value []byte, exp time.Duration) error {
	return s.SetWithContext(context.Background(), key, value, exp)
}

func (s *testStorage) DeleteWithContext(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func (s *testStorage) Delete(key string) error { return s.DeleteWithContext(context.Background(), key) }

func (s *testStorage) ResetWithContext(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = make(map[string][]byte)
	return nil
}

func (s *testStorage) Reset() error { return s.ResetWithContext(context.Background()) }
func (s *testStorage) Close() error { return nil }

func TestAdapterRoundTrip(t *testing.T) {
	t.Parallel()

	storage := newTestStorage()
	store := session.NewStore(session.Config{Storage: storage})
	store.RegisterType(&sessionPayload{})
	adapter := Must[*sessionPayload](store, "sess_admin")

	app := fiber.New()
	var sessionID string
	app.Get("/", func(c fiber.Ctx) error {
		id, err := adapter.Put(c, &sessionPayload{ID: 7, Email: "admin@example.com"})
		require.NoError(t, err)
		sessionID = id

		gotID, payload, ok, err := adapter.Get(c)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, id, gotID)
		require.NotNil(t, payload)
		require.Equal(t, int64(7), payload.ID)

		return c.SendStatus(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotEmpty(t, sessionID)

	byID, ok, err := adapter.GetByID(context.Background(), sessionID)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, byID)
	require.Equal(t, "admin@example.com", byID.Email)
}

func TestAdapterGetReturnsSessionIDWithoutLegacyPayload(t *testing.T) {
	t.Parallel()

	storage := newTestStorage()
	store := session.NewStore(session.Config{Storage: storage})
	adapter := Must[*sessionPayload](store, "sess_admin")

	app := fiber.New()
	app.Get("/seed", func(c fiber.Ctx) error {
		sess, err := store.Get(c)
		require.NoError(t, err)
		defer sess.Release()

		require.NoError(t, sess.Regenerate())
		sess.Set("keepalive", "1")
		require.NoError(t, sess.Save())

		return c.SendStatus(http.StatusOK)
	})

	app.Get("/read", func(c fiber.Ctx) error {
		sessionID, payload, ok, err := adapter.Get(c)
		require.NoError(t, err)
		require.False(t, ok)
		require.Nil(t, payload)
		require.NotEmpty(t, sessionID)
		return c.SendStatus(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/seed", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	cookies := resp.Cookies()
	require.Len(t, cookies, 1)
	require.NoError(t, resp.Body.Close())

	req = httptest.NewRequest(http.MethodGet, "/read", nil)
	req.AddCookie(cookies[0])
	resp, err = app.Test(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
}
