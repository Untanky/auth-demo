package main

import (
	"github.com/Untanky/iam-auth/webauthn"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"

	. "github.com/Untanky/iam-auth/utils"
)

func main() {
	conf, err := ReadConfig()

	db, err := ConnectDB()
	if err != nil {
		panic(err)
	}
	defer db.Close()

	userRepo := &webauthn.SqliteUserRepository{DB: db}
	challengeRepo := &webauthn.InMemoryChallengeRepository{Challenges: map[string]interface{}{}}

	w := webauthn.CreateWebAuthn(&conf.RelyingParty, conf.Authenticator, conf.PublicKeyCredentialParams, challengeRepo)

	router := gin.Default()

	config := cors.DefaultConfig()
	config.AllowOrigins = conf.Cors.Origin
	config.ExposeHeaders = conf.Cors.Headers

	router.Use(cors.New(config))

	authenticationController := webauthn.AuthenticationController{}
	authenticationController.Init(userRepo, challengeRepo, w)
	authenticationController.Routes(router.Group("authenticate"))

	router.Run()
}
