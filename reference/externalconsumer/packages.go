package externalconsumer

// StablePublicPackages is the complete supported pre-v1 import surface.
// Packages omitted from this list are implementation details even when Go
// can import them. Earlier v0.1 consumers must use their immutable tags.
var StablePublicPackages = [...]string{
	"github.com/assurrussa/goauth",
	"github.com/assurrussa/goauth/fiber",
	"github.com/assurrussa/goauth/nethttp",
	"github.com/assurrussa/goauth/oidc",
	"github.com/assurrussa/goauth/oidc/provider",
	"github.com/assurrussa/goauth/oidc/verifier",
	"github.com/assurrussa/goauth/postgres",
	"github.com/assurrussa/goauth/rbac",
	"github.com/assurrussa/goauth/redis",
	"github.com/assurrussa/goauth/testkit",
}

// HostSupportPackages is a compatibility bucket for unavoidable host wiring
// gaps. Keep this list empty before broad external reuse: host wiring should go
// through stable integration packages instead.
var HostSupportPackages = [...]string{}

var SupportedPackages = joinPackageGroups(StablePublicPackages[:], HostSupportPackages[:])

var SupportedPackageCount = len(SupportedPackages)

func joinPackageGroups(groups ...[]string) []string {
	var count int
	for _, group := range groups {
		count += len(group)
	}

	packages := make([]string, 0, count)
	for _, group := range groups {
		packages = append(packages, group...)
	}

	return packages
}
