package embeddedoidc

import (
	"github.com/assurrussa/goauth/internal/legacy/sso"
	oidcprovider "github.com/assurrussa/goauth/oidc/provider"
)

func New(service *oidcprovider.Service) sso.Provider {
	if service == nil {
		return oidcprovider.NewDisabled()
	}

	return service
}

func Disabled() sso.Provider {
	return oidcprovider.NewDisabled()
}
