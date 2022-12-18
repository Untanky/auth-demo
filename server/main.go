package main

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

const (
	webAuthnCreate = "webauthn.create"
	webAuthnGet    = "webauthn.get"
)

type RegisterRequest struct {
	Id       string              `json:"id"`
	Type     string              `json:"type"`
	RawId    URLEncodedBase64    `json:"rawId"`
	Response AttestationResponse `json:"response"`
}

type LoginRequest struct {
	Id       string            `json:"id"`
	Type     string            `json:"type"`
	RawId    URLEncodedBase64  `json:"rawId"`
	Response AssertionResponse `json:"response"`
}

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

func main() {
	userRepo := &InMemoryUserRepository{knownUsers: []*User{}}
	challengeRepo := &InMemoryChallengeRepository{challenges: map[string]interface{}{}}

	relyingParty := &RelyingParty{Id: "localhost", Name: "IAM Auth"}
	publicKeyCredentialsParams := []*PublicKeyCredentialParameter{{Algorithm: -7, Type: "public-key"}}

	webauthn := CreateWebAuthn(relyingParty, "both", publicKeyCredentialsParams, challengeRepo)

	router := gin.Default()

	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:5173"}
	config.ExposeHeaders = []string{"Next-Step"}

	router.Use(cors.New(config))

	authenticationController := AuthenticationController{}
	authenticationController.Init(userRepo, challengeRepo, webauthn)
	authenticationController.Routes(router.Group("authenticate"))

	router.Run()
}
