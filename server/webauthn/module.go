package webauthn

import (
	"github.com/Untanky/iam-auth/core"
	"github.com/gin-gonic/gin"
)

type WebAuthnModule struct {
	controller *AuthenticationController
}

func Init(
	conf *Config,
	userRepo UserRepository,
	registerState core.Cache[string, *RegisterResponse],
	loginState core.Cache[string, *LoginResponse],
	authorizationFinisher core.AuthorizationFinisher,
) (receiver core.Module) {
	webauthnService := CreateWebAuthn(
		&conf.RelyingParty,
		conf.Authenticator,
		conf.PublicKeyCredentialParams,
		registerState,
		loginState,
	)

	controller := AuthenticationController{
		userRepo:              userRepo,
		authZState:            loginState,
		webauthn:              webauthnService,
		authorizationFinisher: authorizationFinisher,
	}

	return &WebAuthnModule{controller: &controller}
}

func (module *WebAuthnModule) SetupRouter(router gin.IRouter) {
	router.POST("/init", module.controller.Authenticate)
	router.POST("/register", module.controller.Register)
	router.POST("/login", module.controller.Login)
}
