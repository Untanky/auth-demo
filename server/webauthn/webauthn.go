package webauthn

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Untanky/iam-auth/core"
	"github.com/Untanky/iam-auth/utils"
)

const (
	webAuthnCreate = "webauthn.create"
	webAuthnGet    = "webauthn.get"
)

type RegisterRequest struct {
	Id       string                 `json:"id"`
	Type     string                 `json:"type"`
	RawId    utils.URLEncodedBase64 `json:"rawId"`
	Response AttestationResponse    `json:"response"`
}

type LoginRequest struct {
	Id       string                 `json:"id"`
	Type     string                 `json:"type"`
	RawId    utils.URLEncodedBase64 `json:"rawId"`
	Response AssertionResponse      `json:"response"`
}

type AuthenticateRequest struct {
	Identifier string `json:"identifier"`
	Challenge  string `json:"challenge"`
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

type RelyingParty struct {
	Name string `json:"name"`
	Id   string `json:"id"`
}

type PublicKeyCredentialParameter struct {
	Algorithm int32  `json:"alg"`
	Type      string `json:"type"`
}

type WebAuthn struct {
	loginState      core.WriteCache[string, *LoginResponse]
	registerState   core.Cache[string, *RegisterResponse]
	relyingParty    *RelyingParty
	authenticator   string // convert to enum
	credentialTypes []*PublicKeyCredentialParameter
}

func CreateWebAuthn(
	relyingParty *RelyingParty,
	authenticator string,
	credentialTypes []*PublicKeyCredentialParameter,
	registerState core.Cache[string, *RegisterResponse],
	loginState core.Cache[string, *LoginResponse],
) *WebAuthn {
	return &WebAuthn{
		relyingParty:    relyingParty,
		authenticator:   authenticator,
		credentialTypes: credentialTypes,
		loginState:      loginState,
		registerState:   registerState,
	}
}

func (webauthn *WebAuthn) BeginRegister(challenge string, user *User) interface{} {
	response := &RegisterResponse{
		Challenge:                      challenge,
		RelyingParty:                   webauthn.relyingParty,
		User:                           &UserResponse{Id: user.Identifier, Name: user.Identifier, DisplayName: user.Identifier},
		PublicKeyCredentialsParameters: webauthn.credentialTypes,
		AuthenticatorSelection: &AuthenticatorSelectionResponse{
			AuthenticatorAttachment: webauthn.authenticator,
		},
		Timeout:     60000,
		Attestation: "direct",
	}

	webauthn.registerState.Set(challenge, response)
	return response
}

func (webauthn *WebAuthn) BeginLogin(challenge string, user *User) interface{} {
	response := &LoginResponse{
		Challenge:        challenge,
		RelyingPartyId:   webauthn.relyingParty.Id,
		AllowCredentials: user.AllowedCredentials(),
		Timeout:          60000,
	}

	webauthn.loginState.Set(challenge, response)
	return response
}

func (webauthn *WebAuthn) FinishRegister(registerRequest RegisterRequest) (*User, error) {
	challengeId, _ := base64.RawStdEncoding.DecodeString(registerRequest.Response.ClientData.Challenge)
	challenge, _ := webauthn.registerState.Get(string(challengeId))

	// Implementation of https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
	err := webauthn.verifyCreateCredentials(challenge, registerRequest.Response)
	if err != nil {
		return nil, err
	}

	webauthn.registerState.Delete(string(challengeId))

	return &User{
		Identifier: challenge.User.Name,
		Credentials: []Credential{
			{
				Id:         registerRequest.Response.AttestationObject.AuthnData.AttData.CredentialID,
				PublicKey:  registerRequest.Response.PublicKey,
				Type:       "public-key",
				Transports: []string{"platform"},
			},
		},
	}, nil
}

func (webauthn *WebAuthn) verifyCreateCredentials(challenge *RegisterResponse, attestationResponse AttestationResponse) error {
	if challenge == nil {
		return fmt.Errorf("No valid challenge found")
	}

	err := webauthn.verifyClientData(attestationResponse.ClientData)
	if err != nil {
		return err
	}

	// TODO: Check attstObj.AuthnData
	// TODO: Check flags
	// TODO: Check algorithm

	// TODO: Implemented https://w3c.github.io/webauthn/#sctn-fido-u2f-attestation

	err = webauthn.verifyKeyAlgorithm(attestationResponse)
	if err != nil {
		return err
	}

	err = webauthn.verifySignature(attestationResponse)
	if err != nil {
		return err
	}

	return nil
}

func (webauthn *WebAuthn) verifyClientData(clientData ClientData) error {
	if clientData.Type != webAuthnCreate {
		return fmt.Errorf("Response type is not 'webauthn.create'; instead found: '%s'", clientData.Type)
	}

	if !strings.Contains(clientData.Origin, webauthn.relyingParty.Id) {
		return fmt.Errorf("Origin is not allowed; got '%s'", clientData.Origin)
	}

	return nil
}

func (webauthn *WebAuthn) verifyKeyAlgorithm(attestationResponse AttestationResponse) error {
	if attestationResponse.PublicKey.GetAlgorithm() != attestationResponse.AttestationObject.AttStmt.Algorithm {
		return fmt.Errorf("Algorithms do not match %d != %d", attestationResponse.PublicKey.GetAlgorithm(), attestationResponse.AttestationObject.AttStmt.Algorithm)
	}

	return nil
}

func (webauthn *WebAuthn) verifySignature(attestationResponse AttestationResponse) error {
	ok, err := attestationResponse.PublicKey.Verify(attestationResponse.VerificationData, attestationResponse.AttestationObject.AttStmt.Signature)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Something went wrong")
	}
	return nil
}

func (webauthn *WebAuthn) FinishLogin(loginRequest *LoginRequest, loginResponse *LoginResponse, user *User) error {
	var publicKey PublicKey
	for i := 0; i < len(user.Credentials); i++ {
		if string(user.Credentials[i].Id) == string(loginRequest.RawId) {
			publicKey = user.Credentials[i].PublicKey
		}
	}

	err := webauthn.verifyClientDataForLogin(&loginRequest.Response)
	if err != nil {
		return err
	}

	err = webauthn.verifySignatureForLogin(&loginRequest.Response, publicKey)
	if err != nil {
		return err
	}

	return nil
}

func (webauthn *WebAuthn) verifyClientDataForLogin(response *AssertionResponse) error {
	if response.ClientData.Type != webAuthnGet {
		return fmt.Errorf("Response type is not 'webauthn.create'; instead found: '%s'", response.ClientData.Type)
	}

	if !strings.Contains(response.ClientData.Origin, "localhost") {
		return fmt.Errorf("Origin is not allowed; got '%s'", response.ClientData.Origin)
	}

	return nil
}

func (webauthn *WebAuthn) verifySignatureForLogin(response *AssertionResponse, publicKey PublicKey) error {
	ok, err := publicKey.Verify(response.VerificationData, response.Signature)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Something went wrong")
	}
	return nil
}
