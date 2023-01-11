package oauth2

import (
	"github.com/Untanky/iam-auth/core"
	"github.com/Untanky/iam-auth/jwt"
	"github.com/Untanky/iam-auth/secret"
	"github.com/gin-gonic/gin"
)

type OAuth2Module struct {
	AuthorizeController *AuthorizeController
	tokenController     *TokenController
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
		AuthorizeController: authorizeController,
	}
}

func (module *OAuth2Module) SetupRouter(router gin.IRouter) {
	router.GET("/authorize", module.AuthorizeController.StartAuthorization)
	router.POST("/authorize", module.AuthorizeController.StartAuthorization)
	router.POST("/token", module.tokenController.CreateAccessToken)
}
