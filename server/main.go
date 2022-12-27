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

	//	userRepo := &webauthn.SqliteUserRepository{DB: db}
	//	challengeRepo := &webauthn.InMemoryChallengeRepository{Challenges: map[string]interface{}{}}

	//	w := webauthn.CreateWebAuthn(&conf.RelyingParty, conf.Authenticator, conf.PublicKeyCredentialParams, challengeRepo)

	router := gin.Default()

	config := cors.DefaultConfig()
	config.AllowOrigins = conf.Cors.Origin
	config.ExposeHeaders = conf.Cors.Headers

	router.Use(cors.New(config))

    service := createAuthorizationService()
	service.SetupRouter(router.Group("api/oauth2/v1"))

	//	authenticationController := webauthn.AuthenticationController{}
	//	authenticationController.Init(userRepo, challengeRepo, w)
	//	authenticationController.Routes(router.Group("authenticate"))

	router.Run()
}

func createAuthorizationService() oauth2.OAuth2Service {
	clientRepo := &utils.InMemoryRepository[oauth2.ClientID, *oauth2.Client]{
		CreateFunc: func() *oauth2.Client {
			return &oauth2.Client{}
		},
		IdFunc: func(client *oauth2.Client) oauth2.ClientID {
			return client.ID
		},
		Store: []*oauth2.Client{},
	}
	challengeRepo := &utils.InMemoryRepository[string, *challenge.Challenge]{
		CreateFunc: func() *challenge.Challenge {
			return &challenge.Challenge{
                Key: challenge.ChallengeKey(utils.RandString(20)),
            }
		},
		IdFunc: func(challenge *challenge.Challenge) string {
			return challenge.GetKey()
		},
		Store: []*challenge.Challenge{},
	}
	codeRepo := &utils.InMemoryRepository[string, *challenge.Code]{
		CreateFunc: func() *challenge.Code {
			return &challenge.Code{
                Key: challenge.CodeKey(utils.RandString(12)),
            }
		},
		IdFunc: func(code *challenge.Code) string {
			return code.GetKey()
		},
		Store: []*challenge.Code{},
	}
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
		challenge.RepoToAuthorizationState[*challenge.Challenge](challengeRepo),
		challenge.RepoToAuthorizationState[*challenge.Code](codeRepo),
		accessTokenService,
		refreshTokenService,
		&consoleLogger,
	)

    return service
}
