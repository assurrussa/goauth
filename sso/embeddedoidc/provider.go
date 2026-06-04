package embeddedoidc

import (
	oidcprovider "github.com/assurrussa/goauth/oidc/provider"
	"github.com/assurrussa/goauth/sso"
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
