package oauth2

import (
	"github.com/Untanky/iam-auth/core"
	"github.com/Untanky/iam-auth/jwt"
	"github.com/Untanky/iam-auth/secret"
	"github.com/gin-gonic/gin"
)

type OAuth2Module struct {
	authorizeController *AuthorizeController
	tokenController     *TokenController
	FinishAuthorization core.AuthorizationFinisher
}

func Init(
	clientRepo core.Repository[ClientID, *Client],
	challengeAuthorizationState core.Cache[string, *AuthorizationRequest],
	codeAuthorizationState core.Cache[string, *AuthorizationRequest],
	accessTokenService jwt.JwtService[secret.KeyPair],
	refreshTokenService jwt.JwtService[secret.SecretString],
	logger core.Logger,
) *OAuth2Module {
	authorizeController := &AuthorizeController{
		authorizationController: authorizationController{
			clientRepo: clientRepo,
			logger:     logger,
		},
		challengeAuthorizationState: challengeAuthorizationState,
		codeAuthorizationState:      codeAuthorizationState,
		accessTokenService:          accessTokenService,
	}

	tokenController := &TokenController{
		authorizationController: authorizationController{
			clientRepo: clientRepo,
			logger:     logger,
		},
		codeState:           codeAuthorizationState,
		accessTokenService:  accessTokenService,
		refreshTokenService: refreshTokenService,
	}

	return &OAuth2Module{
		tokenController:     tokenController,
		authorizeController: authorizeController,
		FinishAuthorization: authorizeController,
	}
}

func (module *OAuth2Module) SetupRouter(router gin.IRouter) {
	router.GET("/authorize", module.authorizeController.StartAuthorization)
	router.POST("/authorize", module.authorizeController.StartAuthorization)
	router.POST("/token", module.tokenController.CreateAccessToken)
}
