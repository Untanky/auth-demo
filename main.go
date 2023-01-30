package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/Untanky/iam-auth/challenge"
	"github.com/Untanky/iam-auth/core"
	"github.com/Untanky/iam-auth/jwt"
	"github.com/Untanky/iam-auth/oauth2"
	"github.com/Untanky/iam-auth/secret"
	"github.com/Untanky/iam-auth/utils"
	"github.com/Untanky/iam-auth/webauthn"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	conf, _ := webauthn.ReadConfig()

	//	db, err := ConnectDB()
	//	if err != nil {
	//		panic(err)
	//	}
	//	defer db.Close()

	if isProduction {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	config := cors.DefaultConfig()
	config.AllowOrigins = conf.Cors.Origin
	config.ExposeHeaders = conf.Cors.Headers

	router.Use(cors.New(config))

	oauth2Module, webauthnModule := createAuthorizationService(conf)
	oauth2Module.SetupRouter(router.Group("api/oauth2/v1"))
	webauthnModule.SetupRouter(router.Group("api/webauthn/v1"))

	if isProduction {
		HostClient(router)
	} else {
		router.NoRoute(ProxyRequest)
	}

	router.Run()
}

func createAuthorizationService(conf *webauthn.Config) (core.Module, core.Module) {
	clientRepo := &utils.InMemoryRepository[oauth2.ClientID, *oauth2.Client]{
		CreateFunc: func() *oauth2.Client {
			return &oauth2.Client{}
		},
		IdFunc: func(client *oauth2.Client) oauth2.ClientID {
			return client.ID
		},
		Store: []*oauth2.Client{},
	}

	clientRepo.Create(&oauth2.Client{
		ClientMetadata: oauth2.ClientMetadata{
			ID:                   "abc",
			Name:                 "Test",
			AuthenticationMethod: oauth2.ClientAuthenticationNone,
			RedirectionURIs:      []string{"http://localhost:3000/finish"},
			ResponseTypes:        []oauth2.ResponseType{oauth2.ResponseTypeCode, oauth2.ResponseTypeToken},
			GrantTypes:           []oauth2.GrantType{oauth2.GrantTypeAuthorizationCode, oauth2.GrantTypeClientCredentials, oauth2.GrantTypePassword},
		},
	})

	userRepo := &webauthn.InMemoryUserRepository{KnownUsers: []*webauthn.User{}}

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

	key, _ := rsa.GenerateKey(rand.Reader, 4096)

	priv, _ := x509.MarshalPKCS8PrivateKey(key)
	// Encode private key to PKCS#1 ASN.1 PEM.
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: priv,
		},
	)

	pub, _ := x509.MarshalPKIXPublicKey(key.Public())
	// Encode public key to PKCS#1 ASN.1 PEM.
	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pub,
		},
	)

	accessTokenService := jwt.JwtService[secret.KeyPair]{
		Method: jwt.RS256,
		Secret: secret.NewSecretPair(secret.KeyPair{
			PublicKey:  secret.NewSecretValue(string(pubPEM)).GetSecret(),
			PrivateKey: secret.NewSecretValue(string(keyPEM)).GetSecret(),
		}),
	}

	refreshKey := make([]byte, 64)
	rand.Read(refreshKey)
	refreshTokenService := jwt.JwtService[secret.SecretString]{
		Method: jwt.HS256,
		Secret: secret.NewSecretValue(string(refreshKey)),
	}
	consoleLogger := utils.ConsoleLogger{}

	oauth2Module := oauth2.Init(
		clientRepo,
		challenge.RepoToAuthorizationState[*challenge.Challenge](challengeRepo),
		challenge.RepoToAuthorizationState[*challenge.Code](codeRepo),
		accessTokenService,
		refreshTokenService,
		&consoleLogger,
	)

	webauthnModule := webauthn.Init(
		conf,
		userRepo,
		challenge.RepoToRegisterState[*challenge.Challenge](challengeRepo),
		challenge.RepoToLoginState[*challenge.Challenge](challengeRepo),
		oauth2Module.FinishAuthorization,
	)

	return oauth2Module, webauthnModule
}
