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
	VerificationData  []byte
	PublicKey         PublicKey
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

    err = response.unmarshalClientData(rawResponse)
    if err != nil {
        return err
    }

    err = response.unmarshalAttestationObject(rawResponse)
    if err != nil {
        return err
    }

	hash := sha256.New()
    hash.Write(rawResponse.ClientDataJSON)
    response.VerificationData = append(response.AttestationObject.RawAuthnData, hash.Sum(nil)...)

	key, err := ParsePublicKey(response.AttestationObject.AuthnData.AttData.CredentialPublicKey)
	response.PublicKey = key

	return nil
}

func (response *CredentialResponse) unmarshalClientData(rawResponse rawCredentialResponse) error {
    var clientData ClientData
    err := json.Unmarshal(rawResponse.ClientDataJSON, &clientData)
    if err != nil {
        return err
    }

    response.ClientData = clientData
    return nil
}

func (response *CredentialResponse) unmarshalAttestationObject(rawResponse rawCredentialResponse) error {
    var attestationObject AttestationObject
    if err := cbor.Unmarshal(rawResponse.AttestationObject, &attestationObject); err != nil {
        return err
    }

    response.AttestationObject = attestationObject
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
    attestationObject.AuthnData = authData

	var attStmt PackedAttestationStatement
	err = cbor.Unmarshal(rawResponse.AttStmt, &attStmt)
	if err != nil {
		return err
    }
    attestationObject.AttStmt = attStmt

	attestationObject.RawAuthnData = rawResponse.AuthnData
	attestationObject.Fmt = rawResponse.Fmt

	return nil
}
