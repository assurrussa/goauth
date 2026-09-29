//nolint:testpackage,lll // Exercises the private PHC parser; fixture strings are deliberately visible.
package goauth

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestPHCRejectsParametersBeforeNarrowingAndDecoding(t *testing.T) {
	salt := base64.RawStdEncoding.EncodeToString(make([]byte, 16))
	hash := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	for _, params := range []string{"m=19456,t=2,p=257", "m=19456,t=2,p=4294967295", "m=19456,m=2,p=1", "m=19456,t=2,x=1", "m=19456,t=4294967295,p=1"} {
		if _, _, _, err := parseArgon2idPHC("$argon2id$v=19$" + params + "$" + salt + "$" + hash); err == nil {
			t.Errorf("unsafe parameters accepted: %s", params)
		}
	}
	for _, phc := range []string{
		"$argon2id$v=19$m=19456,t=2,p=1$" + strings.Repeat("A", 1<<20) + "$" + hash,
		"$argon2id$v=19$m=19456,t=2,p=1$" + salt + "$" + strings.Repeat("A", 200),
	} {
		if _, _, _, err := parseArgon2idPHC(phc); err == nil {
			t.Fatal("oversized encoded material accepted")
		}
	}
}

func FuzzArgon2PHCBounds(f *testing.F) {
	f.Add("$argon2id$v=19$m=19456,t=2,p=257$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Add(strings.Repeat("x", 513))
	f.Fuzz(func(t *testing.T, phc string) {
		params, salt, hash, err := parseArgon2idPHC(phc)
		if err != nil {
			return
		}
		if params.Parallelism > 16 || len(salt) > 64 || len(hash) > 64 {
			t.Fatal("unsafe accepted PHC")
		}
	})
}
