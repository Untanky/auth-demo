package main

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

func CreateWebAuthn(relyingParty *RelyingParty, authenticator string, credentialTypes []*PublicKeyCredentialParameter) *WebAuthn {
	return &WebAuthn{
		relyingParty:    relyingParty,
		authenticator:   authenticator,
		credentialTypes: credentialTypes,
	}
}

func (webauthn *WebAuthn) Authenticate(user *User) interface{} {
	challenge := randStringBytes(20)

    response := webauthn.getAuthenticateResponse(user, challenge)

	webauthn.challengeRepo.Create(&Challenge{
		Value:    challenge,
		Response: response,
	})
    return user
}

func (webauthn *WebAuthn) getAuthenticateResponse(user *User, challenge string) interface{} {
	if user != nil {
		return LoginResponse{
			Challenge:        challenge,
			RelyingPartyId:   webauthn.relyingParty.Id,
			AllowCredentials: user.AllowedCredentials(),
			Timeout:          60000,
		}
	} else {
		return RegisterResponse{
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
	}
}
