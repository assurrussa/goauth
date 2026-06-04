package rolesmiddleware_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/domain/roles/shared"
	rolesmiddleware "github.com/assurrussa/goauth/http/fiber/rolesmiddleware"
)

func TestRequirePermissionGuardDelegatesToPermissionGuard(t *testing.T) {
	t.Parallel()

	optCalled := false
	opt := func(*shared.PermissionGuardConfig) {
		optCalled = true
	}

	key := shared.NewPermissionKey(shared.PermissionDomainRoles, shared.PermissionActionRead)
	stub := &stubPermissionGuard{
		handler: func(c fiber.Ctx) error {
			return c.SendStatus(fiber.StatusAccepted)
		},
	}

	mwGuard := rolesmiddleware.RequirePermissionGuard(stub)

	app := fiber.New()
	app.Use(mwGuard(key, opt))
	app.Get("/", func(c fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	resp, err := app.Test(httptest.NewRequestWithContext(context.Background(), fiber.MethodGet, "/", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusAccepted, resp.StatusCode)
	require.True(t, stub.called)
	require.Equal(t, key, stub.receivedKey)
	require.True(t, optCalled)
}

func TestRequirePermissionUsesProvidedGuard(t *testing.T) {
	t.Parallel()

	optCalled := false
	opt := func(*shared.PermissionGuardConfig) {
		optCalled = true
	}

	key := shared.NewPermissionKey(shared.PermissionDomain("content"), shared.PermissionAction("write"))
	stub := &stubPermissionGuard{
		handler: func(c fiber.Ctx) error {
			return c.SendStatus(fiber.StatusTeapot)
		},
	}

	handler := rolesmiddleware.RequirePermission(stub, key, opt)

	app := fiber.New()
	app.Use(handler)
	app.Get("/", func(c fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	resp, err := app.Test(httptest.NewRequestWithContext(context.Background(), fiber.MethodGet, "/", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusTeapot, resp.StatusCode)
	require.True(t, stub.called)
	require.Equal(t, key, stub.receivedKey)
	require.True(t, optCalled)
}

type stubPermissionGuard struct {
	handler     fiber.Handler
	called      bool
	receivedKey shared.PermissionKey
}

func (s *stubPermissionGuard) Guard(
	key shared.PermissionKey,
	opts ...shared.PermissionGuardOption,
) fiber.Handler {
	s.called = true
	s.receivedKey = key

	cfg := &shared.PermissionGuardConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	if s.handler != nil {
		return s.handler
	}

	return func(c fiber.Ctx) error {
		return c.Next()
	}
}
