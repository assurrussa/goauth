package model

import (
	"database/sql"
	"time"
)

type Role struct {
	ID          int64          `json:"id" db:"id"`
	UUID        string         `json:"uuid" db:"uuid"`
	Slug        string         `json:"slug" db:"slug"`
	Name        string         `json:"name" db:"name"`
	Description sql.NullString `json:"description" db:"description"`
	IsSystem    bool           `json:"isSystem" db:"is_system"`
	CreatedAt   time.Time      `json:"createdAt" db:"created_at"`
	UpdatedAt   time.Time      `json:"updatedAt" db:"updated_at"`
}

func (r Role) HasDescription() bool {
	return r.Description.Valid && r.Description.String != ""
}
