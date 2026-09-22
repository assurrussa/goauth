package cleanerconfirmationcode

import (
	"context"
	"errors"
	"fmt"
	"time"

	logger "github.com/assurrussa/gologger"
)

//go:generate toolsmocks

type storage interface {
	CleanupExpiredCodes(ctx context.Context, batchSize, minutes int) (int64, error)
}

type transactor interface {
	RunInTx(ctx context.Context, f func(context.Context) error) error
}

//go:generate options-gen -out-filename=usecase_options.gen.go -from-struct=Options
type Options struct {
	logger     logger.Logger `option:"mandatory" validate:"required"`
	storage    storage       `option:"mandatory" validate:"required"`
	transactor transactor    `option:"mandatory" validate:"required"`
}

type UseCase struct {
	Options
}

func Must(opts Options) *UseCase {
	useCase, err := New(opts)
	if err != nil {
		panic(err)
	}
	return useCase
}

func New(opts Options) (*UseCase, error) {
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("validate options: %w", err)
	}

	return &UseCase{
		Options: opts,
	}, nil
}

func (u *UseCase) Handle(ctx context.Context, req Request) (Response, error) {
	if req.BatchSize < 100 ||
		req.BatchSize > 5000 ||
		req.Iterations < 1 {
		return Response{}, errors.New("invalid request")
	}

	perIterTimeout := 3 * time.Second
	var total int64
	for i := 0; i < req.Iterations; i++ {
		var totalIterate int64

		err := u.transactor.RunInTx(ctx, func(ctx context.Context) error {
			ctx, cancel := context.WithTimeout(ctx, perIterTimeout)
			defer cancel()

			var err error
			totalIterate, err = u.storage.CleanupExpiredCodes(ctx, req.BatchSize, req.Minutes)
			if err != nil {
				return fmt.Errorf("failed to delete items: %w", err)
			}

			return nil
		})
		if err != nil {
			return Response{}, fmt.Errorf("failed trx: %w", err)
		}

		if totalIterate == 0 {
			break
		}

		total += totalIterate
	}

	return Response{
		Total: total,
	}, nil
}
