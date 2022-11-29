package main

import (
    "crypto/sha256"
    "encoding/json"
	"fmt"
    "strings"

	"github.com/fxamacker/cbor"
)

type RegisterRequest struct {
    Id       string             `json:"id"`
    Type     string             `json:"type"`
    RawId    URLEncodedBase64   `json:"rawId"`
    Response CredentialResponse `json:"response"`
}

// CredentialResponse is the response to a register request done on the client.
type CredentialResponse struct {
	AttestationObject AttestationObject
	ClientDataJSON    ClientData
	ClientDataHash []byte
}

// rawCredentialResponse is the raw response to a register request.
//
// The attestation object is a CBOR encoded byte slice and the ClientDataJSON is JSON encoded byte slice.
type rawCredentialResponse struct {
	AttestationObject URLEncodedBase64 `json:"attestationObject"`
	ClientDataJSON    URLEncodedBase64 `json:"clientDataJSON"`
}

func (response *CredentialResponse) UnmarshalJSON(b []byte) error {
	var rawResponse rawCredentialResponse
	err := json.Unmarshal(b, &rawResponse)
	if err != nil {
		return err
	}

	var clientData ClientData
	err = json.Unmarshal(rawResponse.ClientDataJSON, &clientData)
	if err != nil {
		return err
	}

	var attestationObject AttestationObject
	if err := cbor.Unmarshal(rawResponse.AttestationObject, &attestationObject); err != nil {
		return err
	}

    hash := sha256.New()
    hash.Write(rawResponse.ClientDataJSON)

	response.AttestationObject = attestationObject
    response.ClientDataHash = hash.Sum(nil)
	response.ClientDataJSON = clientData
	return nil
}

type ClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

type AttestationObject struct {
	AuthnData    AuthenticatorData
	RawAuthnData []byte
	Fmt          string
	AttStmt      PackedAttestationStatement
}

type rawAttestationObject struct {
	AuthnData []byte          `cbor:"authData"`
	Fmt       string          `cbor:"fmt"`
	AttStmt   cbor.RawMessage `cbor:"attStmt"`
}

func (attestationObject *AttestationObject) UnmarshalCBOR(b []byte) error {
	var rawResponse rawAttestationObject
	err := cbor.Unmarshal(b, &rawResponse)
	if err != nil {
		return err
	}

	var authData AuthenticatorData
	err = authData.Unmarshal(rawResponse.AuthnData)
	if err != nil {
		return err
	}

	var attStmt PackedAttestationStatement
	err = cbor.Unmarshal(rawResponse.AttStmt, &attStmt)
	if err != nil {
        return err
	}

    attestationObject.AuthnData = authData
    attestationObject.RawAuthnData = rawResponse.AuthnData
	attestationObject.AttStmt = attStmt
	attestationObject.Fmt = rawResponse.Fmt

	return nil
}

const webAuthnCreate = "webauthn.create"

func VertifyCreateCredentials(challenge *AuthenticateResponse, response *CredentialResponse) error {
	if challenge == nil {
		return fmt.Errorf("No valid challenge found")
	}

	if response.ClientDataJSON.Type != webAuthnCreate {
		return fmt.Errorf("Response type is not 'webauthn.create'; instead found: '%s'", response.ClientDataJSON.Type)
	}

	if !strings.Contains(response.ClientDataJSON.Origin, "localhost") {
		return fmt.Errorf("Origin is not allowed; got '%s'", response.ClientDataJSON.Origin)
	}

	key, err := ParsePublicKey(response.AttestationObject.AuthnData.AttData.CredentialPublicKey)

	// TODO: Check attstObj.AuthnData
	// TODO: Check flags
	// TODO: Check algorithm

	// TODO: Implemented https://w3c.github.io/webauthn/#sctn-fido-u2f-attestation

	if key.GetAlgorithm() != response.AttestationObject.AttStmt.Algorithm {
		fmt.Println()
		return fmt.Errorf("Algorithms do not match %d != %d", key.GetAlgorithm(), response.AttestationObject.AttStmt.Algorithm)
	}

	verificationData := append(response.AttestationObject.RawAuthnData, response.ClientDataHash...)
	ok, err := key.Verify(verificationData, response.AttestationObject.AttStmt.Signature)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Something went wrong")
	}
	return nil
}
