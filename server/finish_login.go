package main

import (
	"fmt"
	"strings"
)

const webAuthnGet = "webauthn.get"

type LoginRequest struct {
	Id       string            `json:"id"`
	Type     string            `json:"type"`
	RawId    URLEncodedBase64  `json:"rawId"`
	Response AssertionResponse `json:"response"`
}

func (response *AssertionResponse) VerifyCreateCredentials(challenge *LoginResponse, publicKey PublicKey) error {
	if challenge == nil {
		return fmt.Errorf("No valid challenge found")
	}

	err := response.verifyClientData()
	if err != nil {
		return err
	}

	err = response.verifySignature(publicKey)
	if err != nil {
		return err
	}

	return nil
}

func (response *AssertionResponse) verifyClientData() error {
	if response.ClientData.Type != webAuthnGet {
		return fmt.Errorf("Response type is not 'webauthn.create'; instead found: '%s'", response.ClientData.Type)
	}

	if !strings.Contains(response.ClientData.Origin, "localhost") {
		return fmt.Errorf("Origin is not allowed; got '%s'", response.ClientData.Origin)
	}

	return nil
}

func (response *AssertionResponse) verifySignature(publicKey PublicKey) error {
	ok, err := publicKey.Verify(response.VerificationData, response.Signature)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Something went wrong")
	}
	return nil
}
