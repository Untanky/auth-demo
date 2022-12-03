package main

const webAuthnCreate = "webauthn.create"

type RegisterRequest struct {
	Id       string             `json:"id"`
	Type     string             `json:"type"`
	RawId    URLEncodedBase64   `json:"rawId"`
	Response CredentialResponse `json:"response"`
}
