package oauth2

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
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
	authorizationState AuthorizationState
}

func (controller *AuthorizationController) StartAuthorization(c *gin.Context) {
	var request AuthorizationRequest
	if err := c.BindQuery(&request); err != nil {
		controller.FailAuthorization(&request, invalid_request, c)
		return
	}

	challenge, err := controller.authorizationState.Set(&request)
	if err != nil {
		controller.FailAuthorization(&request, server_error, c)
		fmt.Println(err)
		return
	}

	c.Redirect(http.StatusFound, fmt.Sprintf("%s?challenge=%s", AuthenticationEndpoint, challenge))
}

func (controller *AuthorizationController) FinishAuthorization(request *AuthorizationRequest, c *gin.Context) {

	switch request.ResponseType {
	case ResponseTypeCode:
		response := &AuthorizationResponse{
			Code:  "abc",
			State: request.State,
		}

		c.Redirect(http.StatusFound, fmt.Sprintf("%s?code=%s&state%s", request.RedirectURI, response.Code, response.State))
		break
	case ResponseTypeToken:
		response := &TokenResponse{
			AccessToken: "abc",
			Scope:       request.Scope,
			ExpiresIn:   60 * 60,
			TokenType:   "Bearer",
			State:       request.State,
		}

		c.Redirect(http.StatusFound, fmt.Sprintf(
			"%s?access_token=%s&expires_in=%d&token_type=%s&scope=%s&state%s",
			request.RedirectURI,
			response.AccessToken,
			response.ExpiresIn,
			response.TokenType,
			response.Scope,
			response.State,
		))
		break
	default:
		controller.FailAuthorization(request, unsupported_response_type, c)
	}
}

func (controller *AuthorizationController) FailAuthorization(request *AuthorizationRequest, err oauth2Error, c *gin.Context) {

}
