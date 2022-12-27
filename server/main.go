package main

import (
	"github.com/Untanky/iam-auth/challenge"
	"github.com/Untanky/iam-auth/jwt"
	"github.com/Untanky/iam-auth/oauth2"
	"github.com/Untanky/iam-auth/secret"
	"github.com/Untanky/iam-auth/utils"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	conf, _ := ReadConfig()

	//	db, err := ConnectDB()
	//	if err != nil {
	//		panic(err)
	//	}
	//	defer db.Close()

    var clientRepo utils.Repository[oauth2.ClientID, *oauth2.Client]
	clientRepo = &utils.InMemoryRepository[oauth2.ClientID, *oauth2.Client]{

    }
    var challengeRepo utils.Repository[string, *challenge.Challenge]
    var codeRepo utils.Repository[string, *challenge.Code]
    challengeRepo = &utils.InMemoryRepository[string, *challenge.Challenge]{}
	codeRepo = &utils.InMemoryRepository[string, *challenge.Code]{}
	accessTokenService := jwt.JwtService[secret.KeyPair]{
		Secret: secret.NewSecretPair(secret.KeyPair{
			PublicKey:  secret.NewSecretValue("abc").GetSecret(),
			PrivateKey: secret.NewSecretValue("abc").GetSecret(),
		}),
	}
	refreshTokenService := jwt.JwtService[secret.SecretString]{
		Secret: secret.NewSecretValue("abc"),
	}

	consoleLogger := utils.ConsoleLogger{}

	service := oauth2.OAuth2Service{}
	service.Init(
	    clientRepo,
		challenge.RepoToAuthorizationState(challengeRepo),
		challenge.RepoToAuthorizationState(codeRepo),
		accessTokenService,
		refreshTokenService,
		&consoleLogger,
	)

	//	userRepo := &webauthn.SqliteUserRepository{DB: db}
	//	challengeRepo := &webauthn.InMemoryChallengeRepository{Challenges: map[string]interface{}{}}

	//	w := webauthn.CreateWebAuthn(&conf.RelyingParty, conf.Authenticator, conf.PublicKeyCredentialParams, challengeRepo)

	router := gin.Default()

	config := cors.DefaultConfig()
	config.AllowOrigins = conf.Cors.Origin
	config.ExposeHeaders = conf.Cors.Headers

	router.Use(cors.New(config))

	service.SetupRouter(router.Group("api/oauth2/v1"))

	//	authenticationController := webauthn.AuthenticationController{}
	//	authenticationController.Init(userRepo, challengeRepo, w)
	//	authenticationController.Routes(router.Group("authenticate"))

	router.Run()
}
