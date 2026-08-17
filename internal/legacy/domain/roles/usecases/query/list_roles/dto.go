package listroles

import (
	"strings"

	"github.com/assurrussa/goshared/pkg/validator"
)

type Request struct {
	IDs           []int64  `validate:"omitempty,dive,gt=0"`
	Slugs         []string `validate:"omitempty,dive,required"`
	IncludeSystem bool
	Search        string
	Limit         uint64
	Offset        uint64
}

func (r Request) Validate() error {
	return validator.Validator.Struct(r)
}

func (r Request) normalizedSlugs() []string {
	if len(r.Slugs) == 0 {
		return nil
	}

	s := make([]string, 0, len(r.Slugs))
	for _, slug := range r.Slugs {
		slug = strings.TrimSpace(slug)
		if slug == "" {
			continue
		}
		s = append(s, slug)
	}

	if len(s) == 0 {
		return nil
	}

	return s
}

type Role struct {
	ID       int64  `json:"id"`
	UUID     string `json:"uuid"`
	Slug     string `json:"slug"`
	Name     string `json:"name"`
	IsSystem bool   `json:"isSystem"`
}

type Response struct {
	Roles []Role `json:"roles"`
}
