package core

import (
	"github.com/gin-gonic/gin"
)

type AuthorizationFinisher interface {
	FinishAuthorization(code string, c *gin.Context)
}
