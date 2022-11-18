package main

import (
	"encoding/json"
	"math/rand"
	"net/http"
	"time"

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

	r.Use(cors.New(cors.Config{
		AllowOrigins:  []string{"http://localhost:5001"},
		AllowMethods:  []string{"POST"},
		AllowHeaders:  []string{"Origin"},
		ExposeHeaders: []string{"Content-Length"},
		MaxAge:        12 * time.Hour,
	}))

	r.POST("/api/v1/authenticate", func(c *gin.Context) {
		bodyBytes := []byte{}
		_, err := c.Request.Body.Read(bodyBytes)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Could not parse body",
			})
		}

		body := &AuthenticateBody{}
		err = json.Unmarshal(bodyBytes, body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Could not parse body as JSON",
			})
		}

		challenge := randStringBytes(20)

		challengeMap[challenge] = body.Identifier

		c.JSON(http.StatusOK, gin.H{
			"challenge": challenge,
		})
	})
	r.Run()
}
