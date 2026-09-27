package rcucacheguard_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	logger "github.com/assurrussa/gologger"
	"github.com/assurrussa/goshared/pkg/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	rcucacheguard "github.com/assurrussa/goauth/internal/legacy/domain/roles/cache/rcu/guard"
	rcucacheguardmocks "github.com/assurrussa/goauth/internal/legacy/domain/roles/cache/rcu/guard/mocks"
	listallroles "github.com/assurrussa/goauth/internal/legacy/domain/roles/usecases/query/list_all_roles"
)

type testSuite struct {
	suite.Suite

	mockListAllRoles *rcucacheguardmocks.MockrolesAllUseCase

	svc *rcucacheguard.CacheService
}

func newTestSuite(t *testing.T) (context.Context, context.CancelFunc, *testSuite) {
	t.Helper()

	return tests.NewSuite[*testSuite](t, func(t *testing.T, ctx context.Context) *testSuite {
		t.Helper()

		ctrl := gomock.NewController(t)
		mockListAllRoles := rcucacheguardmocks.NewMockrolesAllUseCase(ctrl)
		mockListAllRoles.EXPECT().Handle(ctx, listallroles.Request{}).Return(listallroles.Response{}, nil).Times(1)

		svc, err := rcucacheguard.NewCache(
			ctx,
			logger.Discard(),
			mockListAllRoles,
			rcucacheguard.WithSyncInterval(300*time.Millisecond),
			rcucacheguard.WithSyncCacheInterval(120*time.Millisecond),
		)
		require.NoError(t, err)

		return &testSuite{
			svc:              svc,
			mockListAllRoles: mockListAllRoles,
		}
	})
}

func TestConfig_ConsumersEnabled(t *testing.T) {
	ctx, _, ts := newTestSuite(t)

	assert.True(t, ts.svc.Enabled(ctx))
}

func TestConfig_ConsumersEnabledWait_Enabled(t *testing.T) {
	ctx, _, ts := newTestSuite(t)
	ts.mockListAllRoles.EXPECT().Handle(ctx, listallroles.Request{}).Return(listallroles.Response{}, nil).AnyTimes()
	finished := atomic.Bool{}
	ctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	go func() {
		<-ctx.Done()
		finished.Store(true)
	}()

	<-ts.svc.EnabledWait(ctx)
	assert.Eventually(t, func() bool {
		return finished.Load() && ts.svc.Enabled(ctx)
	}, 3*time.Second, 10*time.Millisecond)
}

// BenchmarkConfig_ConsumersEnabled-12    	194835848	         6.141 ns/op	       0 B/op	       0 allocs/op.
func BenchmarkConfig_ConsumersEnabled(b *testing.B) {
	ctx := context.Background()
	ctrl := gomock.NewController(b)
	mockListAllRoles := rcucacheguardmocks.NewMockrolesAllUseCase(ctrl)
	mockListAllRoles.EXPECT().Handle(ctx, listallroles.Request{}).Return(listallroles.Response{}, nil).AnyTimes()

	svc, err := rcucacheguard.NewCache(ctx, logger.Discard(), mockListAllRoles)
	require.NoError(b, err)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		svc.Enabled(ctx)
	}
}
