package oauth2

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Untanky/iam-auth/utils"
	"github.com/gin-gonic/gin"
	"golang.org/x/exp/slices"
)

const AuthenticationEndpoint = "/"

type AuthorizeController struct {
    authorizationController
	challengeAuthorizationState utils.WriteCache[string, *AuthorizationRequest]
	codeAuthorizationState      utils.WriteCache[string, *AuthorizationRequest]
}

func (controller *AuthorizeController) StartAuthorization(c *gin.Context) {
	var request AuthorizationRequest
	if err := c.BindQuery(&request); err != nil {
		controller.logger.Error(fmt.Sprintf("Cannot parse query parameters: %s", err))
		controller.failAuthorization(request.State, InvalidRequest, c)
		return
	}

	challenge, err := controller.challengeAuthorizationState.SetWithoutKey(&request)
	if err != nil {
		controller.logger.Error(fmt.Sprintf("Cannot generate challenge: %s", err))
		controller.failAuthorization(request.State, ServerError, c)
		return
	}

	controller.logger.Info(fmt.Sprintf("Startet authorization challenge ('%s')", challenge))
	c.Redirect(http.StatusFound, fmt.Sprintf("%s?challenge=%s", AuthenticationEndpoint, challenge))
}

func (controller *AuthorizeController) FinishAuthorization(request *AuthorizationRequest, c *gin.Context) {
	client, err := controller.clientRepo.FindByID(request.ClientID)
	if err != nil {
		controller.logger.Error(fmt.Sprintf("Client with ID (%s) is not found: %s", request.ClientID, err))
		controller.failAuthorization(request.State, UnauthorizedClient, c)
		return
	}

	if request.RedirectURI == "" {
		controller.logger.Debug("No request URI; using client's first redirection URI.")
		request.RedirectURI = client.RedirectionURIs[0]
	} else if !slices.ContainsFunc(client.RedirectionURIs, func(uri string) bool { return uri == request.RedirectURI }) {
		controller.logger.Error(fmt.Sprintf("Provided redirection URI (%s) not configured with client.", request.RedirectURI))
		controller.failAuthorization(request.State, InvalidRequest, c)
		return
	}

	redirectionURI, err := url.Parse(request.RedirectURI)
	if err != nil {
		controller.logger.Error(fmt.Sprintf("Provided redirection URI (%s) cannot be parsed: %s", request.RedirectURI, err))
		controller.failAuthorization(request.State, InvalidRequest, c)
		return
	}

	if !redirectionURI.Query().Has("state") {
		redirectionURI.Query().Add("state", request.State)
	}

	if !slices.Contains(client.ResponseTypes, request.ResponseType) {
		controller.logger.Error(fmt.Sprintf("Provided response type (%s) is not configured with client.", request.ResponseType))
		controller.RedirectFailedAuthorization(redirectionURI, InvalidRequest, c)
		return
	}

	switch request.ResponseType {
	case ResponseTypeCode:
		controller.logger.Info(fmt.Sprintf("Authorization challenge ('%s') uses 'authorization_code' authorization method", "abc"))

		code, err := controller.codeAuthorizationState.SetWithoutKey(request)
		if err != nil {
			controller.logger.Error(fmt.Sprintf("Cannot generate code: %s", err))
			controller.failAuthorization(request.State, ServerError, c)
			return
		}

		response := &AuthorizationResponse{
			Code:  code,
			State: request.State,
		}
		redirectionURI.Query().Add("code", response.Code)
	case ResponseTypeToken:
		controller.logger.Info(fmt.Sprintf("Authorization challenge ('%s') uses 'implicit' authorization method", "abc"))

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
	default:
		controller.logger.Error(fmt.Sprintf("Provided response type (%s) is unknown.", request.ResponseType))
		controller.RedirectFailedAuthorization(redirectionURI, UnsupportedResponseType, c)
		return
	}

	controller.logger.Info(fmt.Sprintf("Redirecting authorization challenge ('%s') with success", "abc"))
	c.Redirect(http.StatusFound, fmt.Sprint(redirectionURI))
}

func (controller *AuthorizeController) RedirectFailedAuthorization(redirectionURI *url.URL, err OAuth2Error, c *gin.Context) {
	controller.logger.Warn(err)
	redirectionURI.Query().Add("error", err.ErrorType)
	redirectionURI.Query().Add("error_description", err.ErrorDescription)
	if err.ErrorURI != "" {
		redirectionURI.Query().Add("error_uri", err.ErrorURI)
	}

	c.Redirect(http.StatusFound, fmt.Sprint(redirectionURI))
}
