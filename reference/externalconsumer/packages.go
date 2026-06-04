package externalconsumer

// StablePublicPackages are the packages intended to be the reusable goauth API
// for non-host consumers after the first semver release.
var StablePublicPackages = [...]string{
	"github.com/assurrussa/goauth/core",
	"github.com/assurrussa/goauth/http/fiber/rolesmiddleware",
	"github.com/assurrussa/goauth/http/oidcctx",
	"github.com/assurrussa/goauth/integration/adminsession",
	"github.com/assurrussa/goauth/integration/localjwt",
	"github.com/assurrussa/goauth/integration/oidc",
	"github.com/assurrussa/goauth/integration/roles",
	"github.com/assurrussa/goauth/integration/storage",
	"github.com/assurrussa/goauth/local/emailchange",
	"github.com/assurrussa/goauth/local/passwordauth",
	"github.com/assurrussa/goauth/local/passwordchange",
	"github.com/assurrussa/goauth/local/passwordreset",
	"github.com/assurrussa/goauth/local/tokenauth",
	"github.com/assurrussa/goauth/migrations",
	"github.com/assurrussa/goauth/oidc",
	"github.com/assurrussa/goauth/oidc/provider",
	"github.com/assurrussa/goauth/oidc/verifier",
	"github.com/assurrussa/goauth/service/authinvalidator",
	"github.com/assurrussa/goauth/service/authjwtservice",
	"github.com/assurrussa/goauth/service/confirmationcodeservice",
	"github.com/assurrussa/goauth/session/adminaccount",
	"github.com/assurrussa/goauth/session/runtime",
	"github.com/assurrussa/goauth/shared",
	"github.com/assurrussa/goauth/sso",
	"github.com/assurrussa/goauth/sso/embeddedoidc",
	"github.com/assurrussa/goauth/sso/externalidentity",
	"github.com/assurrussa/goauth/sso/identitylink",
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
