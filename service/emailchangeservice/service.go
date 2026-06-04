package emailchangeservice

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"

	authcore "github.com/assurrussa/goauth/core"
	base "github.com/assurrussa/goauth/local/emailchange"
)

var (
	ErrSameEmail    = base.ErrSameEmail
	ErrEmailInUse   = base.ErrEmailInUse
	ErrInvalidEmail = base.ErrInvalidEmail
	ErrInvalidCode  = base.ErrInvalidCode
	ErrCodeExpired  = base.ErrCodeExpired
	ErrMaxAttempts  = base.ErrMaxAttempts
	ErrNotFound     = base.ErrNotFound
	ErrWaitResend   = base.ErrWaitResend
)

const (
	defaultTTL         = 15 * time.Minute
	defaultMaxAttempts = 5
	defaultResendDelay = time.Minute
)

type Subject[T comparable] struct {
	ID          T
	CanonicalID authcore.SubjectID
	Email       string
	Name        string
}

type Request = base.Request

type Pending = base.Pending

type Store[T comparable] interface {
	Upsert(ctx context.Context, subjectID T, req Request) error
	Get(ctx context.Context, subjectID T, forUpdate bool) (Request, error)
	IncrementAttempts(ctx context.Context, subjectID T) error
	Delete(ctx context.Context, subjectID T) error
}

type EmailRepository[T comparable] interface {
	GetByEmail(ctx context.Context, email string) (Subject[T], error)
	UpdateEmail(ctx context.Context, id T, email string) error
}

type OutboxPutter = base.OutboxPutter

type CodeGenerator func() (string, error)

type IsZeroFunc[T comparable] func(T) bool

type Manager[T comparable] interface {
	Request(ctx context.Context, subject Subject[T], newEmail, clientIP string) error
	Confirm(ctx context.Context, subject Subject[T], code string) (string, error)
	GetPending(ctx context.Context, subjectID T) (*Pending, error)
}

type Options[T comparable] struct {
	Store       Store[T]
	Repo        EmailRepository[T]
	Outbox      OutboxPutter
	CodeGen     CodeGenerator
	IsZeroID    IsZeroFunc[T]
	TTL         time.Duration
	MaxAttempts int
	ResendDelay time.Duration
}

type Service[T comparable] struct {
	base *base.Service
	ids  *subjectIDMapper[T]
}

func NewService[T comparable](opts Options[T]) (*Service[T], error) {
	switch {
	case opts.Store == nil:
		return nil, errors.New("email change service: store is required")
	case opts.Repo == nil:
		return nil, errors.New("email change service: repo is required")
	case opts.Outbox == nil:
		return nil, errors.New("email change service: outbox is required")
	case opts.IsZeroID == nil:
		return nil, errors.New("email change service: IsZeroID is required")
	}

	if opts.TTL <= 0 {
		opts.TTL = defaultTTL
	}
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = defaultMaxAttempts
	}
	if opts.ResendDelay <= 0 {
		opts.ResendDelay = defaultResendDelay
	}

	ids := newSubjectIDMapper[T]()
	baseSvc, err := base.New(base.Options{
		Store:       storeAdapter[T]{store: opts.Store, ids: ids},
		Repo:        repoAdapter[T]{repo: opts.Repo, isZeroID: opts.IsZeroID, ids: ids},
		Outbox:      opts.Outbox,
		CodeGen:     opts.CodeGen,
		TTL:         opts.TTL,
		MaxAttempts: opts.MaxAttempts,
		ResendDelay: opts.ResendDelay,
	})
	if err != nil {
		return nil, fmt.Errorf("build goauth email change service: %w", err)
	}

	return &Service[T]{base: baseSvc, ids: ids}, nil
}

func (s *Service[T]) Request(ctx context.Context, subject Subject[T], newEmail, clientIP string) error {
	s.rememberSubject(subject)

	return s.base.Request(ctx, authcore.Subject{
		ID:    authSubjectID(subject),
		Email: subject.Email,
		Name:  subject.Name,
	}, newEmail, clientIP)
}

func (s *Service[T]) Confirm(ctx context.Context, subject Subject[T], code string) (string, error) {
	s.rememberSubject(subject)

	return s.base.Confirm(ctx, authcore.Subject{
		ID:    authSubjectID(subject),
		Email: subject.Email,
		Name:  subject.Name,
	}, code)
}

func (s *Service[T]) GetPending(ctx context.Context, subjectID T) (*Pending, error) {
	return s.base.GetPending(ctx, encodeID(subjectID))
}

func (s *Service[T]) rememberSubject(subject Subject[T]) {
	if s == nil || s.ids == nil {
		return
	}
	subjectID := authSubjectID(subject)
	if subjectID.IsZero() {
		return
	}

	s.ids.Store(subjectID.String(), subject.ID)
}

type storeAdapter[T comparable] struct {
	store Store[T]
	ids   *subjectIDMapper[T]
}

func (a storeAdapter[T]) Upsert(ctx context.Context, subjectID string, req base.Request) error {
	id, err := a.decodeID(subjectID)
	if err != nil {
		return err
	}
	return a.store.Upsert(ctx, id, req)
}

func (a storeAdapter[T]) Get(ctx context.Context, subjectID string, forUpdate bool) (base.Request, error) {
	id, err := a.decodeID(subjectID)
	if err != nil {
		return base.Request{}, err
	}
	return a.store.Get(ctx, id, forUpdate)
}

func (a storeAdapter[T]) IncrementAttempts(ctx context.Context, subjectID string) error {
	id, err := a.decodeID(subjectID)
	if err != nil {
		return err
	}
	return a.store.IncrementAttempts(ctx, id)
}

func (a storeAdapter[T]) Delete(ctx context.Context, subjectID string) error {
	id, err := a.decodeID(subjectID)
	if err != nil {
		return err
	}
	return a.store.Delete(ctx, id)
}

func (a storeAdapter[T]) decodeID(subjectID string) (T, error) {
	if a.ids != nil {
		if id, ok := a.ids.Load(subjectID); ok {
			return id, nil
		}
	}

	return decodeID[T](subjectID)
}

type repoAdapter[T comparable] struct {
	repo     EmailRepository[T]
	isZeroID IsZeroFunc[T]
	ids      *subjectIDMapper[T]
}

func (a repoAdapter[T]) GetByEmail(ctx context.Context, email string) (authcore.Subject, error) {
	subject, err := a.repo.GetByEmail(ctx, email)
	if err != nil {
		return authcore.Subject{}, err
	}
	if a.isZeroID(subject.ID) {
		return authcore.Subject{}, nil
	}

	return authcore.Subject{
		ID:    authSubjectID(subject),
		Email: subject.Email,
		Name:  subject.Name,
	}, nil
}

func authSubjectID[T comparable](subject Subject[T]) authcore.SubjectID {
	if !subject.CanonicalID.IsZero() {
		return subject.CanonicalID
	}

	switch value := any(subject.ID).(type) {
	case authcore.SubjectID:
		return value
	default:
		return authcore.SubjectID{}
	}
}

func (a repoAdapter[T]) UpdateEmail(ctx context.Context, subjectID, email string) error {
	id, err := a.decodeID(subjectID)
	if err != nil {
		return err
	}
	return a.repo.UpdateEmail(ctx, id, email)
}

func (a repoAdapter[T]) decodeID(subjectID string) (T, error) {
	if a.ids != nil {
		if id, ok := a.ids.Load(subjectID); ok {
			return id, nil
		}
	}

	return decodeID[T](subjectID)
}

func (a repoAdapter[T]) MarkEmailConfirmed(context.Context, string, time.Time) error {
	return nil
}

func encodeID[T comparable](id T) string {
	switch value := any(id).(type) {
	case string:
		return value
	case authcore.SubjectID:
		return value.String()
	case sharedtypes.UserID:
		return value.String()
	default:
		return fmt.Sprint(id)
	}
}

func decodeID[T comparable](raw string) (T, error) {
	var zero T

	switch any(zero).(type) {
	case string:
		return any(raw).(T), nil
	case authcore.SubjectID:
		id, err := authcore.ParseSubjectIDString(raw)
		if err != nil {
			return zero, err
		}
		return any(id).(T), nil
	case int64:
		val, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return zero, fmt.Errorf("parse int64 subject id: %w", err)
		}
		return any(val).(T), nil
	case int:
		val, err := strconv.Atoi(raw)
		if err != nil {
			return zero, fmt.Errorf("parse int subject id: %w", err)
		}
		return any(val).(T), nil
	case sharedtypes.UserID:
		var id sharedtypes.UserID
		if err := id.UnmarshalText([]byte(raw)); err != nil {
			return zero, fmt.Errorf("parse user id: %w", err)
		}
		return any(id).(T), nil
	default:
		return zero, fmt.Errorf("unsupported subject id type %T", zero)
	}
}

type subjectIDMapper[T comparable] struct {
	mu  sync.RWMutex
	ids map[string]T
}

func newSubjectIDMapper[T comparable]() *subjectIDMapper[T] {
	return &subjectIDMapper[T]{ids: make(map[string]T)}
}

func (m *subjectIDMapper[T]) Store(subjectID string, id T) {
	if m == nil || subjectID == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.ids[subjectID] = id
}

func (m *subjectIDMapper[T]) Load(subjectID string) (T, bool) {
	var zero T
	if m == nil || subjectID == "" {
		return zero, false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.ids[subjectID]
	return id, ok
}
