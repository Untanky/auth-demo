package oauth2

import (
	"github.com/Untanky/iam-auth/utils"
	"github.com/gin-gonic/gin"
)

type authorizationController struct {
	clientRepo utils.ViewRepository[ClientID, *Client]
	logger     utils.Logger
}

func (controller *authorizationController) failAuthorization(state string, err OAuth2Error, c *gin.Context) {
	controller.logger.Warn(err)

	response := ErrorResponse{
		OAuth2Error: err,
		State:       state,
	}
	c.JSON(response.StatusCode, response)
}
