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
		controller.failAuthorization(&request, InvalidRequest, c)
		return
	}

	challenge, err := controller.authorizationState.Set(&request)
	if err != nil {
		controller.failAuthorization(&request, ServerError, c)
		fmt.Println(err)
		return
	}

	c.Redirect(http.StatusFound, fmt.Sprintf("%s?challenge=%s", AuthenticationEndpoint, challenge))
}

func (controller *AuthorizationController) FinishAuthorization(request *AuthorizationRequest, c *gin.Context) {
	client, err := controller.clientRepo.FindClient(request.ClientID)
	if err != nil {
		controller.failAuthorization(request, UnauthorizedClient, c)
		return
	}

	if request.RedirectURI == "" {
		request.RedirectURI = client.RedirectionURIs[0]
	} else if !slices.ContainsFunc(client.RedirectionURIs, func(uri string) bool { return uri == request.RedirectURI }) {
		controller.failAuthorization(request, InvalidRequest, c)
		return
	}

	redirectionURI, err := url.Parse(request.RedirectURI)
	if err != nil {
		controller.failAuthorization(request, InvalidRequest, c)
		return
	}

	if !redirectionURI.Query().Has("state") {
		redirectionURI.Query().Add("state", request.State)
	}

	if !slices.Contains(client.ResponseTypes, request.ResponseType) {
		controller.RedirectFailedAuthorization(redirectionURI, InvalidRequest, c)
		return
	}

	switch request.ResponseType {
	case ResponseTypeCode:
		response := &AuthorizationResponse{
			Code:  "abc",
			State: request.State,
		}

		redirectionURI.Query().Add("code", response.Code)
		break
	case ResponseTypeToken:
		response := &TokenResponse{
			AccessToken: "abc",
			Scope:       request.Scope,
			ExpiresIn:   60 * 60,
			TokenType:   "Bearer",
			State:       request.State,
		}

		redirectionURI.Query().Add("access_token", response.AccessToken)
		redirectionURI.Query().Add("scope", strings.Join(request.Scope, ""))
		redirectionURI.Query().Add("expires_in", fmt.Sprint(response.ExpiresIn))
		redirectionURI.Query().Add("token_type", response.TokenType)
		break
	default:
		controller.RedirectFailedAuthorization(redirectionURI, UnsupportedResponseType, c)
		return
	}

	c.Redirect(http.StatusFound, fmt.Sprint(redirectionURI))
}

func (controller *AuthorizationController) failAuthorization(request *AuthorizationRequest, err OAuth2Error, c *gin.Context) {
	response := ErrorResponse{
		OAuth2Error: err,
		State:       request.State,
	}

	c.JSON(response.StatusCode, response)
}

func (controller *AuthorizationController) RedirectFailedAuthorization(redirectionURI *url.URL, err OAuth2Error, c *gin.Context) {
	redirectionURI.Query().Add("error", err.ErrorType)
	redirectionURI.Query().Add("error_description", err.ErrorDescription)
	if err.ErrorURI != "" {
		redirectionURI.Query().Add("error_uri", err.ErrorURI)
	}

	c.Redirect(http.StatusFound, fmt.Sprint(redirectionURI))
}
