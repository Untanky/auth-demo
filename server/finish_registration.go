package main

import (
	"fmt"
	"strings"
)

const webAuthnCreate = "webauthn.create"

type RegisterRequest struct {
	Id       string             `json:"id"`
	Type     string             `json:"type"`
	RawId    URLEncodedBase64   `json:"rawId"`
	Response CredentialResponse `json:"response"`
}

func (response *CredentialResponse) VerifyCreateCredentials(challenge *RegisterResponse) error {
	if challenge == nil {
		return fmt.Errorf("No valid challenge found")
	}

	err := response.verifyClientData()
	if err != nil {
		return err
	}

	// TODO: Check attstObj.AuthnData
	// TODO: Check flags
	// TODO: Check algorithm

	// TODO: Implemented https://w3c.github.io/webauthn/#sctn-fido-u2f-attestation

	err = response.verifyKeyAlgorithm()
	if err != nil {
		return err
	}

	err = response.verifySignature()
	if err != nil {
		return err
	}

	return nil
}

func (response *CredentialResponse) verifyClientData() error {
	if response.ClientData.Type != webAuthnCreate {
		return fmt.Errorf("Response type is not 'webauthn.create'; instead found: '%s'", response.ClientData.Type)
	}

	if !strings.Contains(response.ClientData.Origin, "localhost") {
		return fmt.Errorf("Origin is not allowed; got '%s'", response.ClientData.Origin)
	}

	return nil
}

func (response *CredentialResponse) verifyKeyAlgorithm() error {
	if response.PublicKey.GetAlgorithm() != response.AttestationObject.AttStmt.Algorithm {
		return fmt.Errorf("Algorithms do not match %d != %d", response.PublicKey.GetAlgorithm(), response.AttestationObject.AttStmt.Algorithm)
	}

	return nil
}

func (response *CredentialResponse) verifySignature() error {
	ok, err := response.PublicKey.Verify(response.VerificationData, response.AttestationObject.AttStmt.Signature)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Something went wrong")
	}
	return nil
}
