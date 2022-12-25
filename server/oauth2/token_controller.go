package oauth2

import (
	"encoding/base64"
	"fmt"
	"github.com/Untanky/iam-auth/utils"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
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

	client, _ := controller.clientRepo.FindClient(request.ClientId)
	controller.authenticate(client, c)

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
	case GrantTypeRefreshToken:
		var refreshTokenRequest RefreshTokenRequest
		if err := c.BindQuery(&refreshTokenRequest); err != nil {
			controller.logger.Error(fmt.Sprintf("Cannot parse query parameters: %s", err))
			controller.failAuthorization(InvalidRequest, c)
			return
		}

		// TODO: check if refresh token is valid
		// TODO: check if refresh token was authored to the client
	case GrantTypePassword:
		fallthrough
	default:
		controller.logger.Error(fmt.Sprintf("Grant type (%s) not supported", request.GrantType))
		controller.failAuthorization(UnsupportedGrantType, c)
		return
	}

	c.JSON(http.StatusOK, tokenResponse)
}

func (controller *TokenController) authenticate(client *Client, c *gin.Context) bool {
    if client == nil {
        basicClient, ok := controller.authenticateWithBasicAuth(c)
        client = basicClient
        return ok
    }

	switch client.AuthenticationMethod {
	case ClientSecretBasic:
        basicClient, ok := controller.authenticateWithBasicAuth(c)
        if basicClient.ID != client.ID {
            controller.logger.Error("Client from basic auth and request params do not match")
            return false
        }
        return ok
	case ClientAuthenticationNone:
		return true
	case ClientSecretPost:
		fallthrough
	case ClientPrivateKey:
		fallthrough
	case ClientSecretJWT:
		controller.logger.Error("Client cannot be authenticated")
		c.Header("WWW-Authenticate", "Basic")
		controller.failAuthorization(InvalidClient, c)
		return false
	}
}

func (controller *TokenController) authenticateWithBasicAuth(c *gin.Context) (*Client, bool) {

}

func (controller *TokenController) failAuthorization(err OAuth2Error, c *gin.Context) {
	controller.logger.Warn(err)

	response := ErrorResponse{
		OAuth2Error: err,
	}
	c.JSON(response.StatusCode, response)
}
