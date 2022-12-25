package challenge

import (
	"github.com/Untanky/iam-auth/oauth2"
)

type codeKey string

func generateCodeKey() codeKey {
	return codeKey(utils.RandStringBytes(12))
}

// A stateful authorization code
type code struct {
	key           codeKey
	authorization *oauth2.AuthorizationRequest
}

func (code *code) GetKey() string {
	return string(code.key)
}

func (code *code) GetAuthorizationState() *oauth2.AuthorizationRequest {
	return code.authorization
}

func (code *code) BindAuthorizationState(request *oauth2.AuthorizationRequest) {
	code.authorization = request
}
