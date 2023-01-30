package oauth2

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/Untanky/iam-auth/core"
	"github.com/Untanky/iam-auth/jwt"
	"github.com/Untanky/iam-auth/secret"
	"github.com/gin-gonic/gin"
)

type TokenController struct {
	authorizationController
	codeState           core.ReadCache[string, *AuthorizationRequest]
	accessTokenService  jwt.JwtService[secret.KeyPair]
	refreshTokenService jwt.JwtService[secret.SecretString]
}

func (controller *TokenController) CreateAccessToken(c *gin.Context) {
	var request TokenRequest
	if err := c.BindQuery(&request); err != nil {
		controller.logger.Error(fmt.Sprintf("Cannot parse query parameters: %s", err))
		controller.failAuthorization("", InvalidRequest, c)
		return
	}

	client, _ := controller.clientRepo.FindByID(request.ClientId)
	if !controller.authenticate(client, c) {
		return
	}

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
			controller.failAuthorization("", InvalidRequest, c)
			return
		}

		authorizationRequest, err := controller.codeState.Get(authorizationCodeRequest.Code)
		if err != nil {
			controller.logger.Error(fmt.Sprintf("Authorization code not found: %s", err))
			controller.failAuthorization("", InvalidGrant, c)
			return
		}

		// if authorizationRequest.RedirectURI != authorizationCodeRequest.RedirectURI {
		// 	controller.logger.Error("Redirect URIs do not match between authorize and token endpoint")
		// 	controller.failAuthorization(authorizationRequest.State, InvalidGrant, c)
		// 	return
		// }

		if authorizationRequest.ClientID != client.ID {
			controller.logger.Error(fmt.Sprintf("Authorization code was issued to another client (request client: %s, code client: %s)", authorizationRequest.ClientID, client.ID))
			controller.failAuthorization(authorizationRequest.State, InvalidGrant, c)
			return
		}

		tokenResponse.State = authorizationRequest.State
	case GrantTypeRefreshToken:
		var refreshTokenRequest RefreshTokenRequest
		if err := c.BindQuery(&refreshTokenRequest); err != nil {
			controller.logger.Error(fmt.Sprintf("Cannot parse query parameters: %s", err))
			controller.failAuthorization("", InvalidRequest, c)
			return
		}

		// TODO: check if refresh token is valid
		// TODO: check if refresh token was authored to the client
	case GrantTypePassword:
		fallthrough
	default:
		controller.logger.Error(fmt.Sprintf("Grant type (%s) not supported", request.GrantType))
		controller.failAuthorization("", UnsupportedGrantType, c)
		return
	}

	accessToken, err := controller.accessTokenService.Create(map[string]interface{}{})
	if err != nil {
		controller.logger.Error(fmt.Sprintf("Failed to generate access token: %s", err))
		controller.failAuthorization("", ServerError, c)
		return
	}
	tokenResponse.AccessToken = string(accessToken)

	if request.GrantType != GrantTypeRefreshToken {
		refreshToken, err := controller.refreshTokenService.Create(map[string]interface{}{})
		if err != nil {
			controller.logger.Error(fmt.Sprintf("Failed to generate refresh token: %s", err))
			controller.failAuthorization("", ServerError, c)
			return
		}
		tokenResponse.RefreshToken = string(refreshToken)
	}

	c.JSON(http.StatusOK, tokenResponse)
}

func (controller *TokenController) authenticate(client *Client, c *gin.Context) bool {
	if client == nil {
		clientAuthentication := c.Request.Header.Get("Authorization")
		basicClient, err := controller.authenticateWithBasicAuth(clientAuthentication)
		if err != nil {
			controller.failAuthorization("", *err, c)
			return false
		}
		client = basicClient
		return true
	}

	switch client.AuthenticationMethod {
	case ClientSecretBasic:
		clientAuthentication := c.Request.Header.Get("Authorization")
		basicClient, err := controller.authenticateWithBasicAuth(clientAuthentication)
		if err != nil {
			controller.failAuthorization("", *err, c)
			return false
		}
		if basicClient.ID != client.ID {
			controller.logger.Error("Client from basic auth and request params do not match")
			controller.failAuthorization("", InvalidClient, c)
			return false
		}
		return true
	case ClientAuthenticationNone:
		return true
	}

	controller.logger.Error("Client cannot be authenticated")
	c.Header("WWW-Authenticate", "Basic")
	controller.failAuthorization("", InvalidClient, c)
	return false
}

func (controller *TokenController) authenticateWithBasicAuth(clientAuthentication string) (*Client, *OAuth2Error) {
	if !strings.HasPrefix("Basic", clientAuthentication) {
		return nil, &InvalidClient
	}
	basicAuthentication := clientAuthentication[6:]
	decodedBasicAuth, err := base64.RawURLEncoding.DecodeString(basicAuthentication)
	if err != nil {
		controller.logger.Error(fmt.Sprintf("Client cannot be authenticated"))
		return nil, &InvalidClient
	}
	basicAuthComponents := strings.Split(string(decodedBasicAuth), ":")
	clientID, password := ClientID(basicAuthComponents[0]), basicAuthComponents[1]

	client, err := controller.clientRepo.FindByID(clientID)
	if err != nil {
		controller.logger.Error(fmt.Sprintf("Client could not be found: %s", err))
		return nil, &InvalidClient
	}

	if string(client.Secret) != password {
		controller.logger.Error(fmt.Sprintf("Client secret does not match: %s", err))
		return nil, &InvalidClient
	}

	return client, nil
}