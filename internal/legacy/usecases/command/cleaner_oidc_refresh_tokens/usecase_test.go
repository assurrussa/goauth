package cleaneroidcrefreshtokens_test

import (
	"context"
	"errors"
	"testing"

	"github.com/assurrussa/goshared/pkg/logger"
	"github.com/stretchr/testify/require"

	cleaneroidcrefreshtokens "github.com/assurrussa/goauth/internal/legacy/usecases/command/cleaner_oidc_refresh_tokens"
)

func TestHandleSuccess(t *testing.T) {
	t.Parallel()

	storage := &stubStorage{results: []int64{2, 1, 0}}
	useCase := cleaneroidcrefreshtokens.Must(
		cleaneroidcrefreshtokens.NewOptions(logger.Discard(), storage, stubTransactor{}),
	)

	response, err := useCase.Handle(context.Background(), cleaneroidcrefreshtokens.Request{
		BatchSize:  100,
		Iterations: 5,
		Minutes:    60,
	})
	require.NoError(t, err)
	require.Equal(t, int64(3), response.Total)
	require.Equal(t, 3, storage.calls)
}

func TestHandleInvalidRequest(t *testing.T) {
	t.Parallel()

	useCase := cleaneroidcrefreshtokens.Must(
		cleaneroidcrefreshtokens.NewOptions(logger.Discard(), &stubStorage{}, stubTransactor{}),
	)

	_, err := useCase.Handle(context.Background(), cleaneroidcrefreshtokens.Request{
		BatchSize:  10,
		Iterations: 0,
		Minutes:    60,
	})
	require.Error(t, err)
}

func TestHandleStorageError(t *testing.T) {
	t.Parallel()

	useCase := cleaneroidcrefreshtokens.Must(
		cleaneroidcrefreshtokens.NewOptions(logger.Discard(), &stubStorage{err: errors.New("boom")}, stubTransactor{}),
	)

	_, err := useCase.Handle(context.Background(), cleaneroidcrefreshtokens.Request{
		BatchSize:  100,
		Iterations: 1,
		Minutes:    60,
	})
	require.ErrorContains(t, err, "failed trx")
}

type stubStorage struct {
	results []int64
	err     error
	calls   int
}

func (s *stubStorage) CleanupExpiredTokens(_ context.Context, _, _ int) (int64, error) {
	s.calls++
	if s.err != nil {
		return 0, s.err
	}
	if len(s.results) == 0 {
		return 0, nil
	}

	result := s.results[0]
	s.results = s.results[1:]

	return result, nil
}

type stubTransactor struct{}

func (stubTransactor) RunInTx(ctx context.Context, f func(context.Context) error) error {
	return f(ctx)
}
