package oauth2

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/exp/slices"
)

const AuthenticationEndpoint = "/"

type ClientRepository interface {
	FindClient(clientID clientID) (*ClientMetadata, error)
}

type AuthorizationState interface {
	Get(key string) (*AuthorizationRequest, error)
	Set(request *AuthorizationRequest) (string, error)
}

type AuthorizationController struct {
	clientRepo         ClientRepository
	authorizationState AuthorizationState
}

func (controller *AuthorizationController) StartAuthorization(c *gin.Context) {
	var request AuthorizationRequest
	if err := c.BindQuery(&request); err != nil {
		controller.failAuthorization(&request, invalid_request, c)
		return
	}

	challenge, err := controller.authorizationState.Set(&request)
	if err != nil {
		controller.failAuthorization(&request, server_error, c)
		fmt.Println(err)
		return
	}

	c.Redirect(http.StatusFound, fmt.Sprintf("%s?challenge=%s", AuthenticationEndpoint, challenge))
}

func (controller *AuthorizationController) FinishAuthorization(request *AuthorizationRequest, c *gin.Context) {
	client, err := controller.clientRepo.FindClient(request.ClientID)
	if err != nil {
		controller.failAuthorization(request, unauthorized_client, c)
		return
	}

	if !slices.Contains(client.ResponseTypes, request.ResponseType) {
		controller.failAuthorization(request, invalid_request, c)
		return
	}

	if request.RedirectURI == "" {
		request.RedirectURI = client.RedirectionURIs[0]
	} else if !slices.ContainsFunc(client.RedirectionURIs, func(uri string) bool { return uri == request.RedirectURI }) {
		controller.failAuthorization(request, invalid_request, c)
		return
	}

	redirectionUrl, err := url.Parse(request.RedirectURI)
	if err != nil {
		controller.failAuthorization(request, invalid_request, c)
		return
	}

	if !redirectionUrl.Query().Has("state") {
		redirectionUrl.Query().Add("state", request.State)
	}

	switch request.ResponseType {
	case ResponseTypeCode:
		response := &AuthorizationResponse{
			Code:  "abc",
			State: request.State,
		}

		redirectionUrl.Query().Add("code", response.Code)
		break
	case ResponseTypeToken:
		response := &TokenResponse{
			AccessToken: "abc",
			Scope:       request.Scope,
			ExpiresIn:   60 * 60,
			TokenType:   "Bearer",
			State:       request.State,
		}

		redirectionUrl.Query().Add("access_token", response.AccessToken)
		redirectionUrl.Query().Add("scope", strings.Join(request.Scope, ""))
		redirectionUrl.Query().Add("expires_in", fmt.Sprint(response.ExpiresIn))
		redirectionUrl.Query().Add("token_type", response.TokenType)
		break
	default:
		controller.failAuthorization(request, unsupported_response_type, c)
		return
	}

	c.Redirect(http.StatusFound, fmt.Sprint(redirectionUrl))
}

func (controller *AuthorizationController) failAuthorization(request *AuthorizationRequest, err oauth2Error, c *gin.Context) {

}

func (controller *AuthorizationController) RedirectFailAuthorization(request *AuthorizationRequest, err oauth2Error, c *gin.Context) {

}
