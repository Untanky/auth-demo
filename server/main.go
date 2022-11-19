package main

import (
	"fmt"
	"math/rand"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type AuthenticateRequest struct {
	Identifier string `json:"identifier"`
}

type RelyingPartyResponse struct {
	Name string `json:"name"`
	Id   string `json:"id"`
}

type UserReponse struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type PublicKeyCredentialsResponse struct {
	Algorithm int32  `json:"alg"`
	Type      string `json:"type"`
}

type AuthenticatorSelectionResponse struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment"`
}

type AuthenticateResponse struct {
	Challenge                      string                         `json:"challenge"`
	RelyingParty                   RelyingPartyResponse           `json:"rp"`
	User                           UserReponse                    `json:"user"`
	PublicKeyCredentialsParameters []PublicKeyCredentialsResponse `json:"pubKeyCredParams"`
	AuthenticatorSelection         AuthenticatorSelectionResponse `json:"authenticatorSelection"`
	Timeout                        int32                          `json:"timeout"`
	Attestation                    string                         `json:"attestation"`
}

type CredentialReponse struct {
	AttestationObject string `json:"attestationObject"`
	ClientDataJSON    string `json:"clientDataJSON"`
}

type RegisterRequest struct {
	Id      string            `json:"id"`
	Type    string            `json:"type"`
	RawId   string            `json:"rawId"`
	Reponse CredentialReponse `json:"response"`
}

type RegisterResponse struct {
	Challenge string
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
	knownIdentifiers := []string{}

	relyingParty := RelyingPartyResponse{Id: "localhost", Name: "IAM Auth"}
	authenticatorSelection := AuthenticatorSelectionResponse{AuthenticatorAttachment: "both"}
	publicKeyCredentialsParams := []PublicKeyCredentialsResponse{{Algorithm: -7, Type: "public-key"}}

	router := gin.Default()

	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:5501"}
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

		var response AuthenticateResponse

		isIdentifierKnown := false
		for i := 0; i < len(knownIdentifiers); i++ {
			if body.Identifier == knownIdentifiers[i] {
				isIdentifierKnown = true
			}
		}

		if isIdentifierKnown {
			c.Header("Next-Step", "login")
		} else {
			c.Header("Next-Step", "register")
			response = AuthenticateResponse{
				Challenge:                      randStringBytes(20),
				RelyingParty:                   relyingParty,
				User:                           UserReponse{Id: "abc", Name: body.Identifier, DisplayName: "Lukas"},
				PublicKeyCredentialsParameters: publicKeyCredentialsParams,
				AuthenticatorSelection:         authenticatorSelection,
				Timeout:                        60000,
				Attestation:                    "direct",
			}
		}

		challengeMap[response.Challenge] = body.Identifier

		c.JSON(http.StatusOK, response)
	})

	router.POST("/register", func(c *gin.Context) {
		body := RegisterRequest{}

		if err := c.ShouldBind(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "could not parse body",
			})
			fmt.Println("Error", err)
			return
		}

		fmt.Println(body.Id)

		// Implementation of https://w3c.github.io/webauthn/#sctn-registering-a-new-credential

		c.JSON(http.StatusOK, nil)
	})

	router.POST("/login", func(c *gin.Context) {
		body := AuthenticateRequest{}
		if err := c.ShouldBind(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "could not parse body",
			})
			fmt.Println(err)
			return
		}

		// Implementation of https://w3c.github.io/webauthn/#sctn-verifying-assertion

		response := AuthenticateResponse{
			Challenge: randStringBytes(20),
		}

		challengeMap[response.Challenge] = body.Identifier

		c.JSON(http.StatusOK, response)
	})

	router.Run()
}
