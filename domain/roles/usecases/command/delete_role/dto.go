package deleterole

import (
	"github.com/assurrussa/goshared/pkg/validator"
)

type Request struct {
	RoleID int64 `validate:"gt=0"`
}

func (r Request) Validate() error {
	return validator.Validator.Struct(r)
}

type Response struct{}
