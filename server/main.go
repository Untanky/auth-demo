package main

import (
	"fmt"
	"math/rand"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type AuthenticateBody struct {
	Identifier string
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func main() {
	challengeMap := map[string]string{}

	r := gin.Default()

	r.Use(cors.Default())

	r.POST("/authenticate", func(c *gin.Context) {
		body := AuthenticateBody{}
		if err := c.ShouldBind(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "could not parse body",
			})
			fmt.Println(err)
			return
		}

		challenge := randStringBytes(20)

		challengeMap[challenge] = body.Identifier

		c.JSON(http.StatusOK, gin.H{
			"challenge": challenge,
		})
	})
	r.Run()
}
