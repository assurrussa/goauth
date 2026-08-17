package shared

import (
	"database/sql/driver"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

var (
	ErrSubjectIDUuidZero = errors.New("SubjectID uuid is zero")
	SubjectIDNil         = SubjectID(uuid.Nil)
)

type SubjectID uuid.UUID                             //
func NewSubjectID() SubjectID                        { return SubjectID(uuid.New()) }
func (t SubjectID) String() string                   { return uuid.UUID(t).String() }
func (t SubjectID) Value() (driver.Value, error)     { return t.String(), nil }
func (t *SubjectID) Scan(src any) error              { return (*uuid.UUID)(t).Scan(src) }
func (t SubjectID) MarshalText() ([]byte, error)     { return uuid.UUID(t).MarshalText() }
func (t *SubjectID) UnmarshalText(data []byte) error { return (*uuid.UUID)(t).UnmarshalText(data) }
func (t SubjectID) IsZero() bool                     { return t == SubjectIDNil }
func (t SubjectID) Matches(x any) bool {
	v, ok := x.(SubjectID)
	if !ok {
		return false
	}

	return t == v
}

func (t SubjectID) Validate() error {
	if t.IsZero() {
		return fmt.Errorf("validate: %w", ErrSubjectIDUuidZero)
	}
	return nil
}

func (t SubjectID) AsPointer() *SubjectID {
	if t.IsZero() {
		return nil
	}
	return &t
}

type TypeSet = interface {
	SubjectID
}

func Parse[T TypeSet](s string) (T, error) {
	v, err := uuid.Parse(s)
	return T(v), err
}

func MustParse[T TypeSet](s string) T {
	return T(uuid.MustParse(s))
}
