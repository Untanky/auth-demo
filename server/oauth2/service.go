package oauth2

import (
	"github.com/Untanky/iam-auth/jwt"
	"github.com/Untanky/iam-auth/secret"
	"github.com/Untanky/iam-auth/utils"
	"github.com/gin-gonic/gin"
)

type OAuth2Service struct {
	AuthorizeController *AuthorizeController
	tokenController     *TokenController
}

func (receiver *OAuth2Service) Init(
	clientRepo utils.Repository[ClientID, *Client],
	challengeAuthorizationState utils.WriteCache[string, *AuthorizationRequest],
	codeAuthorizationState utils.Cache[string, *AuthorizationRequest],
	accessTokenService jwt.JwtService[secret.KeyPair],
	refreshTokenService jwt.JwtService[secret.SecretString],
	logger utils.Logger,
) {
	receiver.AuthorizeController = &AuthorizeController{
		authorizationController: authorizationController{
			clientRepo: clientRepo,
			logger:     logger,
		},
		challengeAuthorizationState: challengeAuthorizationState,
		codeAuthorizationState:      codeAuthorizationState,
		accessTokenService:          accessTokenService,
	}

	receiver.tokenController = &TokenController{
		authorizationController: authorizationController{
			clientRepo: clientRepo,
			logger:     logger,
		},
		codeState:           codeAuthorizationState,
		accessTokenService:  accessTokenService,
		refreshTokenService: refreshTokenService,
	}
}

func (receiver *OAuth2Service) SetupRouter(router gin.IRouter) {
	router.GET("/authorize", receiver.AuthorizeController.StartAuthorization)
	router.POST("/authorize", receiver.AuthorizeController.StartAuthorization)
	router.POST("/token", receiver.tokenController.CreateAccessToken)
}
