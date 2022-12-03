package main

import (
	"encoding/base64"
	"fmt"
	"strings"
)

type RelyingParty struct {
	Name string `json:"name"`
	Id   string `json:"id"`
}

type PublicKeyCredentialParameter struct {
	Algorithm int32  `json:"alg"`
	Type      string `json:"type"`
}

type WebAuthn struct {
	challengeRepo   ChallengeRepository
	relyingParty    *RelyingParty
	authenticator   string // convert to enum
	credentialTypes []*PublicKeyCredentialParameter
}

func CreateWebAuthn(relyingParty *RelyingParty, authenticator string, credentialTypes []*PublicKeyCredentialParameter, challengeRepo ChallengeRepository) *WebAuthn {
	return &WebAuthn{
		relyingParty:    relyingParty,
		authenticator:   authenticator,
		credentialTypes: credentialTypes,
		challengeRepo:   challengeRepo,
	}
}

func (webauthn *WebAuthn) BeginRegister(user *User) interface{} {
	challenge := randStringBytes(20)

	response := RegisterResponse{
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

	webauthn.challengeRepo.Create(&Challenge{
		Value:    challenge,
		Response: response,
	})
	return response
}

func (webauthn *WebAuthn) BeginLogin(user *User) interface{} {
	challenge := randStringBytes(20)

	response := LoginResponse{
		Challenge:        challenge,
		RelyingPartyId:   webauthn.relyingParty.Id,
		AllowCredentials: user.AllowedCredentials(),
		Timeout:          60000,
	}

	webauthn.challengeRepo.Create(&Challenge{
		Value:    challenge,
		Response: response,
	})
	return response
}

func (webauthn *WebAuthn) FinishRegister(registerRequest RegisterRequest) (*User, error) {
	challengeId, _ := base64.RawStdEncoding.DecodeString(registerRequest.Response.ClientData.Challenge)
	challenge, _ := webauthn.challengeRepo.FindByValue(string(challengeId))

	// Implementation of https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
	r := (challenge.Response.(RegisterResponse))
	err := webauthn.verifyCreateCredentials(&r, registerRequest.Response)
	if err != nil {
		return nil, err
	}

	webauthn.challengeRepo.DeleteByValue(string(challengeId))

	return &User{
		Identifier: r.User.Name,
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

func (webauthn *WebAuthn) verifyCreateCredentials(challenge *RegisterResponse, attestationResponse CredentialResponse) error {
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

func (webauthn *WebAuthn) verifyKeyAlgorithm(attestationResponse CredentialResponse) error {
	if attestationResponse.PublicKey.GetAlgorithm() != attestationResponse.AttestationObject.AttStmt.Algorithm {
		return fmt.Errorf("Algorithms do not match %d != %d", attestationResponse.PublicKey.GetAlgorithm(), attestationResponse.AttestationObject.AttStmt.Algorithm)
	}

	return nil
}

func (webauthn *WebAuthn) verifySignature(attestationResponse CredentialResponse) error {
	ok, err := attestationResponse.PublicKey.Verify(attestationResponse.VerificationData, attestationResponse.AttestationObject.AttStmt.Signature)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Something went wrong")
	}
	return nil
}