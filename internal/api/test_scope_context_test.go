package api

import (
	"context"

	"github.com/identrail/identrail/internal/db"
)

func defaultScopeContext() context.Context {
	return db.WithScope(context.Background(), db.Scope{})
}
