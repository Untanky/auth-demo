package main

import (
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
)

func HostClient(router gin.IRouter) {
	router.Use(static.Serve("/", static.LocalFile("./client", false)))
}
