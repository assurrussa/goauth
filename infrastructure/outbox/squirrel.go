package outbox

import (
	sq "github.com/Masterminds/squirrel"
	querybuilder "github.com/assurrussa/outbox/shared/query_builder"
)

type Eq querybuilder.Eq

func BuilderDollar() sq.StatementBuilderType {
	return querybuilder.BuilderDollar()
}
