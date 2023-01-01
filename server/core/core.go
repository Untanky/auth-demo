package core

import "github.com/gin-gonic/gin"

type Module interface {
	SetupRouter(router gin.IRouter)
}
