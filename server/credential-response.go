package main

import (
    "crypto/sha256"
    "encoding/json"

    "github.com/fxamacker/cbor"
)

// CredentialResponse is the response to a register or login request done on the client.
type CredentialResponse struct {
	AttestationObject AttestationObject
	ClientData        ClientData
	ClientDataHash    []byte
	VerificationData  []byte
	PublicKey         PublicKey
}

func (response *CredentialResponse) UnmarshalJSON(b []byte) error {
    var rawResponse struct {
        AttestationObject URLEncodedBase64 `json:"attestationObject"`
        ClientDataJSON    URLEncodedBase64 `json:"clientDataJSON"`
    }
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

	key, err := ParsePublicKey(attestationObject.AuthnData.AttData.CredentialPublicKey)

	response.AttestationObject = attestationObject
	response.ClientData = clientData
	response.ClientDataHash = hash.Sum(nil)
	response.VerificationData = append(attestationObject.RawAuthnData, hash.Sum(nil)...)
	response.PublicKey = key
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

func (attestationObject *AttestationObject) UnmarshalCBOR(b []byte) error {
    var rawResponse struct {
        AuthnData []byte          `cbor:"authData"`
        Fmt       string          `cbor:"fmt"`
        AttStmt   cbor.RawMessage `cbor:"attStmt"`
    }
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
