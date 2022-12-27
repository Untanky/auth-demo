package challenge

import (
	"github.com/Untanky/iam-auth/oauth2"
    "github.com/Untanky/iam-auth/utils"
)

type codeKey string

func generateCodeKey() codeKey {
	return codeKey(utils.RandString(12))
}

// A stateful authorization Code
type Code struct {
	key           codeKey
	authorization *oauth2.AuthorizationRequest
}

func (code *Code) GetKey() string {
	return string(code.key)
}

func (code *Code) GetAuthorizationState() *oauth2.AuthorizationRequest {
	return code.authorization
}

func (code *Code) BindAuthorizationState(request *oauth2.AuthorizationRequest) {
	code.authorization = request
}
