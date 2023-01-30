package core

import "github.com/gin-gonic/gin"

// A module grouping functionality
type Module interface {
	SetupRouter(router gin.IRouter)
}
