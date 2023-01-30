package webauthn

import (
	"crypto/sha256"
	"encoding/json"

	. "github.com/Untanky/iam-auth/utils"
)

// AssertionResponse is the response to a register or login request done on the client.
type AssertionResponse struct {
	ClientData        ClientData        `json:"clientDataJSON"`
	AuthenticatorData AuthenticatorData `json:"authenticatorData"`
	Signature         []byte            `json:"signature"`
	UserHandle        string            `json:"userHandle"`
	VerificationData  []byte
}

type rawAssertionResponse struct {
	ClientDataJSON    URLEncodedBase64 `json:"clientDataJSON"`
	AuthenticatorData URLEncodedBase64 `json:"authenticatorData"`
	Signature         URLEncodedBase64 `json:"signature"`
	UserHandle        URLEncodedBase64 `json:"userHandle"`
}

func (response *AssertionResponse) UnmarshalJSON(b []byte) error {
	var rawResponse rawAssertionResponse
	err := json.Unmarshal(b, &rawResponse)
	if err != nil {
		return err
	}

	var clientData ClientData
	err = json.Unmarshal(rawResponse.ClientDataJSON, &clientData)
	if err != nil {
		return err
	}

	response.ClientData = clientData

	var authenticatorData AuthenticatorData
	if err := authenticatorData.Unmarshal(rawResponse.AuthenticatorData); err != nil {
		return err
	}

	response.AuthenticatorData = authenticatorData

	hash := sha256.New()
	hash.Write(rawResponse.ClientDataJSON)
	response.VerificationData = append(rawResponse.AuthenticatorData, hash.Sum(nil)...)

	response.UserHandle = string(rawResponse.UserHandle)
	response.Signature = rawResponse.Signature
	return nil
}
