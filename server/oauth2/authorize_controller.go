package oauth2

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

const AuthenticationEndpoint = "/"

func Authorize(c *gin.Context) {
	var request AuthorizationRequest
	if err := c.BindQuery(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "could not parse query",
		})
		fmt.Println(err)
		return
	}

	c.Redirect(http.StatusFound, AuthenticationEndpoint)
}
