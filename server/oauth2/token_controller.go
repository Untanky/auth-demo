package oauth2

import (
	"fmt"
	"github.com/Untanky/iam-auth/utils"
	"github.com/gin-gonic/gin"
	"net/http"
)

type TokenController struct {
	clientRepo ClientRepository
	codeState  AuthorizationState
	logger     utils.Logger
}

func (controller *TokenController) CreateAccessToken(c *gin.Context) {
	var request TokenRequest
	if err := c.BindQuery(&request); err != nil {
		controller.logger.Error(fmt.Sprintf("Cannot parse query parameters: %s", err))
		controller.failAuthorization(InvalidRequest, c)
		return
	}

    // TODO: Authenticate client

    tokenResponse := TokenResponse{
        TokenType: "Bearer",
        ExpiresIn: 60 * 60,
        Scope:     request.Scope,
    }

	switch request.GrantType {
	case GrantTypeAuthorizationCode:
		var authorizationCodeRequest AuthorizationCodeTokenRequest
		if err := c.BindQuery(&authorizationCodeRequest); err != nil {
			controller.logger.Error(fmt.Sprintf("Cannot parse query parameters: %s", err))
			controller.failAuthorization(InvalidRequest, c)
			return
		}

        authorizationRequest, err := controller.codeState.Get(authorizationCodeRequest.Code)
        if err != nil {
            controller.logger.Error(fmt.Sprintf("Authorization code not found: %s", err))
            controller.failAuthorization(InvalidGrant, c)
        }

        if authorizationRequest.RedirectURI != authorizationCodeRequest.RedirectURI {
            controller.logger.Error("Redirect URIs do not match between authorize and token endpoint")
            controller.failAuthorization(InvalidGrant, c)
        }

        tokenResponse.State = authorizationRequest.State
		break
	case GrantTypeRefreshToken:
		var refreshTokenRequest AuthorizationCodeTokenRequest
		if err := c.BindQuery(&refreshTokenRequest); err != nil {
			controller.logger.Error(fmt.Sprintf("Cannot parse query parameters: %s", err))
			controller.failAuthorization(InvalidRequest, c)
			return
		}
		break
	case GrantTypePassword:
	default:
		controller.logger.Error(fmt.Sprintf("Grant type (%s) not supported", request.GrantType))
        controller.failAuthorization(UnsupportedGrantType, c)
        return
	}

	c.JSON(http.StatusOK, tokenResponse)
}

func (controller *TokenController) failAuthorization(err OAuth2Error, c *gin.Context) {
	controller.logger.Warn(err)

	response := ErrorResponse{
		OAuth2Error: err,
	}
	c.JSON(response.StatusCode, response)
}
