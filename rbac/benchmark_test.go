package rbac_test

import (
	"context"
	"testing"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/rbac"
)

// BenchmarkCheck measures in-process service overhead with fixed test doubles.
// It does not measure PostgreSQL, network caches, or cache invalidation.
func BenchmarkCheck(b *testing.B) {
	cases := []struct {
		name         string
		storeAllowed bool
		cache        rbac.Cache
		wantAllowed  bool
	}{
		{name: "uncached_allow", storeAllowed: true, wantAllowed: true},
		{name: "uncached_deny"},
		{name: "cache_hit_allow", cache: cacheStub{allowed: true, found: true}, wantAllowed: true},
		{name: "cache_hit_deny", storeAllowed: true, cache: cacheStub{found: true}},
		{name: "cache_miss", storeAllowed: true, cache: cacheStub{}, wantAllowed: true},
	}
	for _, test := range cases {
		b.Run(test.name, func(b *testing.B) {
			service, err := rbac.New(&storeStub{allowed: test.storeAllowed}, test.cache)
			if err != nil {
				b.Fatal(err)
			}
			ctx := context.Background()
			subjectID := goauth.NewSubjectID()
			key := rbac.MustPermissionKey("content", "read")

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				allowed, err := service.Check(ctx, subjectID, key)
				if err != nil {
					b.Fatal(err)
				}
				if allowed != test.wantAllowed {
					b.Fatalf("Check allowed = %t, want %t", allowed, test.wantAllowed)
				}
			}
		})
	}
}
