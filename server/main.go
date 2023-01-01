package main

import (
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

	router := gin.Default()

	config := cors.DefaultConfig()
	config.AllowOrigins = conf.Cors.Origin
	config.ExposeHeaders = conf.Cors.Headers

	router.Use(cors.New(config))

	oauth2Module, webauthnModule, _ := createAuthorizationService(conf)
	oauth2Module.SetupRouter(router.Group("api/oauth2/v1"))
	webauthnModule.SetupRouter(router.Group("api/webauthn/v1"))

	router.NoRoute(ProxyRequest)

	router.Run()
}

func createAuthorizationService(conf *webauthn.Config) (core.Module, core.Module, utils.Repository[string, *challenge.Challenge]) {
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
			RedirectionURIs:      []string{"http://localhost:8080/finish"},
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
	accessTokenService := jwt.JwtService[secret.KeyPair]{
		Method: jwt.RS256,
		Secret: secret.NewSecretPair(secret.KeyPair{
			PublicKey: secret.NewSecretValue(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`).GetSecret(),
			PrivateKey: secret.NewSecretValue(`-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
dn/RsYEONbwQSjIfMPkvxF+8HQ==
-----END PRIVATE KEY-----`).GetSecret(),
		}),
	}
	refreshTokenService := jwt.JwtService[secret.SecretString]{
		Method: jwt.HS256,
		Secret: secret.NewSecretValue("abc"),
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
		challenge.RepoToAuthorizationState[*challenge.Challenge](challengeRepo),
		oauth2Module.AuthorizeController,
	)

	return oauth2Module, webauthnModule, challengeRepo
}
