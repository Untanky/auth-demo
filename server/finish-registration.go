package main

import (
	"fmt"
	"strings"

	"github.com/fxamacker/cbor"
)

type AttestationObject struct {
	AuthnData []byte          `cbor:"authData"`
	Fmt       string          `cbor:"fmt"`
	AttStmt   cbor.RawMessage `cbor:"attStmt"`
}

const webAuthnCreate = "webauthn.create"

func VertifyCreateCredentials(challenge *AuthenticateResponse, clientData *ClientData, attestationObject *AttestationObject, hash []byte) error {
	if challenge == nil {
		return fmt.Errorf("No valid challenge found")
	}

	if clientData.Type != webAuthnCreate {
		return fmt.Errorf("Response type is not 'webauthn.create'; instead found: '%s'", clientData.Type)
	}

	if !strings.Contains(clientData.Origin, "localhost") {
		return fmt.Errorf("Origin is not allowed; got '%s'", clientData.Origin)
	}

	var authData AuthenticatorData
	err := authData.Unmarshal(attestationObject.AuthnData)
	if err != nil {
		return err
	}

	key, err := ParsePublicKey(authData.AttData.CredentialPublicKey)

	// TODO: Check attstObj.AuthnData
	// TODO: Check flags
	// TODO: Check algorithm

	// TODO: Implemented https://w3c.github.io/webauthn/#sctn-fido-u2f-attestation

	var attStmt PackedAttestationStatement
	err = cbor.Unmarshal([]byte(attestationObject.AttStmt), &attStmt)
	if err != nil {
		fmt.Println(err)
	}

	if key.GetAlgorithm() != attStmt.Algorithm {
		fmt.Println()
		return fmt.Errorf("Algorithms do not match %d != %d", key.GetAlgorithm(), attStmt.Algorithm)
	}

	verificationData := append(attestationObject.AuthnData, hash...)

	ok, err := key.Verify(verificationData, attStmt.Signature)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Something went wrong")
	}
	return nil
}
