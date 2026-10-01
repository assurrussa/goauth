package postgres

import (
	"database/sql"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"weak"

	"github.com/assurrussa/goauth/rbac"
)

// Only weak references escape service ownership: the registry cannot retain
// a database, delegate cache or transaction wrapper after its owner releases it.
type rbacCacheScope struct {
	cache    weak.Pointer[transactionCache]
	disabled atomic.Bool
}

var rbacCacheScopes = struct {
	sync.Mutex
	entries map[weak.Pointer[sql.DB]]*rbacCacheScope
}{entries: make(map[weak.Pointer[sql.DB]]*rbacCacheScope)}

func shareTransactionCache(db *sql.DB, cache rbac.Cache, invalidator rbac.CacheInvalidator) *transactionCache {
	key := weak.Make(db)
	rbacCacheScopes.Lock()
	defer rbacCacheScopes.Unlock()
	scope, exists := rbacCacheScopes.entries[key]
	if exists {
		current := scope.cache.Value()
		if cache != nil && current != nil && sameRBACCache(current.delegate, cache) {
			return current
		}
		// A different/nil cache or a collected wrapper cannot prove that the
		// delegate is safe. All services on this DB keep authoritative reads.
		scope.disabled.Store(true)
	} else {
		scope = &rbacCacheScope{}
		rbacCacheScopes.entries[key] = scope
		runtime.AddCleanup(db, removeRBACCacheScope, key)
	}
	if cache == nil {
		return nil
	}
	wrapped := &transactionCache{db: db, delegate: cache, invalidator: invalidator, scope: scope}
	if scope.cache.Value() == nil {
		scope.cache = weak.Make(wrapped)
	}
	return wrapped
}

func sameRBACCache(one, two rbac.Cache) bool {
	return reflect.ValueOf(one).Comparable() && reflect.ValueOf(two).Comparable() && one == two
}

func removeRBACCacheScope(key weak.Pointer[sql.DB]) {
	rbacCacheScopes.Lock()
	defer rbacCacheScopes.Unlock()
	delete(rbacCacheScopes.entries, key)
}
