package challenge

import (
	"github.com/Untanky/iam-auth/oauth2"
	"github.com/Untanky/iam-auth/utils"
    "github.com/Untanky/iam-auth/webauthn"
)

type ChallengeKey string

func generateChallengeKey() ChallengeKey {
	return ChallengeKey(utils.RandString(32))
}

// A stateful authorization Challenge
type Challenge struct {
	Key           ChallengeKey
    authorization *oauth2.AuthorizationRequest
    loginResponse *webauthn.LoginResponse
    registerResponse *webauthn.RegisterResponse
}

func (challenge *Challenge) GetKey() string {
    return string(challenge.Key)
}

func (challenge *Challenge) GetAuthorizationState() *oauth2.AuthorizationRequest {
    return challenge.authorization
}

func (challenge *Challenge) BindAuthorizationState(request *oauth2.AuthorizationRequest) {
    challenge.authorization = request
}

func (challenge *Challenge) GetLoginState() *webauthn.LoginResponse {
    return challenge.loginResponse
}

func (challenge *Challenge) BindLoginState(request *webauthn.LoginResponse) {
    challenge.loginResponse = request
}

func (challenge *Challenge) GetRegisterState() *webauthn.RegisterResponse {
    return challenge.registerResponse
}

func (challenge *Challenge) BindRegisterState(request *webauthn.RegisterResponse) {
    challenge.registerResponse = request
}
