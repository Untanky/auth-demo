package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type AuthenticateRequest struct {
	Identifier string `json:"identifier"`
}

type UserResponse struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type AllowCredentialResponse struct {
	Id         []byte   `json:"id"`
	Type       string   `json:"type"`
	Transports []string `json:"transports"`
}

type AuthenticatorSelectionResponse struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment"`
}

type RegisterResponse struct {
	Challenge                      string                          `json:"challenge"`
	RelyingParty                   *RelyingParty                   `json:"rp"`
	User                           *UserResponse                   `json:"user"`
	PublicKeyCredentialsParameters []*PublicKeyCredentialParameter `json:"pubKeyCredParams"`
	AuthenticatorSelection         *AuthenticatorSelectionResponse `json:"authenticatorSelection"`
	Timeout                        int32                           `json:"timeout"`
	Attestation                    string                          `json:"attestation"`
}

type LoginResponse struct {
	Challenge        string                    `json:"challenge"`
	RelyingPartyId   string                    `json:"rpId"`
	AllowCredentials []AllowCredentialResponse `json:"allowCredentials"`
	Timeout          int32                     `json:"timeout"`
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
	userRepo := &InMemoryUserRepository{knownUsers: []*User{}}
	challengeRepo := &InMemoryChallengeRepository{challenges: map[string]interface{}{}}

	relyingParty := &RelyingParty{Id: "localhost", Name: "IAM Auth"}
	publicKeyCredentialsParams := []*PublicKeyCredentialParameter{{Algorithm: -7, Type: "public-key"}}

	webauthn := CreateWebAuthn(relyingParty, "platform", publicKeyCredentialsParams)

	router := gin.Default()

	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:5500"}
	config.ExposeHeaders = []string{"Next-Step"}

	router.Use(cors.New(config))

	router.POST("/authenticate", func(c *gin.Context) {
		body := AuthenticateRequest{}
		if err := c.ShouldBind(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "could not parse body",
			})
			fmt.Println(err)
			return
		}

		user, _ := userRepo.FindByIdentifier(body.Identifier)
		response := webauthn.Authenticate(user)
		c.JSON(http.StatusOK, response)
	})

	router.POST("/register", func(c *gin.Context) {
		body := RegisterRequest{}
		err := json.NewDecoder(c.Request.Body).Decode(&body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "could not parse body",
			})
			fmt.Println("Error", err)
			return
		}

		challengeId, _ := base64.RawStdEncoding.DecodeString(body.Response.ClientData.Challenge)
		challenge, _ := challengeRepo.FindByValue(string(challengeId))

		// Implementation of https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
		r := (challenge.Response.(RegisterResponse))
		err = body.Response.VerifyCreateCredentials(&r)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
		}

		userRepo.Create(&User{
			Identifier: r.User.Name,
			Credentials: []Credential{
				{
					Id:         body.Response.AttestationObject.AuthnData.AttData.CredentialID,
					PublicKey:  body.Response.PublicKey,
					Type:       "public-key",
					Transports: []string{"platform"},
				},
			},
		})

		challengeRepo.DeleteByValue(string(challengeId))

		c.JSON(http.StatusOK, nil)
	})

	router.POST("/login", func(c *gin.Context) {
		body := LoginRequest{}
		if err := c.ShouldBind(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "could not parse body",
			})
			fmt.Println(err)
			return
		}

		// Implementation of https://w3c.github.io/webauthn/#sctn-verifying-assertion
		challengeId, _ := base64.RawStdEncoding.DecodeString(body.Response.ClientData.Challenge)
		challenge, _ := challengeRepo.FindByValue(string(challengeId))

		// Implementation of https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
		r := (challenge.Response.(LoginResponse))
		user, err := userRepo.FindByIdentifier(body.Response.UserHandle)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		var publicKey PublicKey
		for i := 0; i < len(user.Credentials); i++ {
			if string(user.Credentials[i].Id) == string(body.RawId) {
				publicKey = user.Credentials[i].PublicKey
			}
		}

		err = body.Response.VerifyCreateCredentials(&r, publicKey)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, nil)
	})

	router.Run()
}
