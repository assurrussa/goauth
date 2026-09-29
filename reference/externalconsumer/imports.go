package externalconsumer

import (
	_ "github.com/assurrussa/goauth" // dependency
	_ "github.com/assurrussa/goauth/fiber"
	_ "github.com/assurrussa/goauth/nethttp"
	_ "github.com/assurrussa/goauth/oidc"
	_ "github.com/assurrussa/goauth/oidc/provider"
	_ "github.com/assurrussa/goauth/oidc/verifier"
	_ "github.com/assurrussa/goauth/postgres"
	_ "github.com/assurrussa/goauth/rbac"
	_ "github.com/assurrussa/goauth/redis"
	_ "github.com/assurrussa/goauth/testkit"
)
