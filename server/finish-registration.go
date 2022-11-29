package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor"
)


type CredentialResponse struct {
	AttestationObject AttestationObject `json:"attestationObject"`
	ClientDataJSON    ClientData       `json:"clientDataJSON"`
	RawClientDataJSON URLEncodedBase64
}

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

    response.AttestationObject = attestationObject

	response.RawClientDataJSON = rawResponse.ClientDataJSON
	response.ClientDataJSON = clientData
	return nil
}

type RegisterRequest struct {
	Id      string             `json:"id"`
	Type    string             `json:"type"`
	RawId    URLEncodedBase64   `json:"rawId"`
	Response CredentialResponse `json:"response"`
}

type ClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

type AttestationObject struct {
    AuthnData AuthenticatorData
    RawAuthnData []byte
    Fmt       string
    AttStmt   PackedAttestationStatement
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
    attestationObject.AuthnData = authData
    attestationObject.RawAuthnData = rawResponse.AuthnData



    var attStmt PackedAttestationStatement
    err = cbor.Unmarshal(rawResponse.AttStmt, &attStmt)
    if err != nil {
        fmt.Println(err)
    }

    attestationObject.AttStmt = attStmt
    attestationObject.Fmt = rawResponse.Fmt

    return nil
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

	key, err := ParsePublicKey(attestationObject.AuthnData.AttData.CredentialPublicKey)

	// TODO: Check attstObj.AuthnData
	// TODO: Check flags
	// TODO: Check algorithm

	// TODO: Implemented https://w3c.github.io/webauthn/#sctn-fido-u2f-attestation

	if key.GetAlgorithm() != attestationObject.AttStmt.Algorithm {
		fmt.Println()
		return fmt.Errorf("Algorithms do not match %d != %d", key.GetAlgorithm(), attestationObject.AttStmt.Algorithm)
	}

	verificationData := append(attestationObject.RawAuthnData, hash...)

	ok, err := key.Verify(verificationData, attestationObject.AttStmt.Signature)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Something went wrong")
	}
	return nil
}
