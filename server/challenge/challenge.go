package challenge

import (
	"github.com/Untanky/iam-auth/oauth2"
	"github.com/Untanky/iam-auth/utils"
)

type challengeKey string

func generateChallengeKey() challengeKey {
	return challengeKey(utils.RandString(32))
}

// A stateful authorization Challenge
type Challenge struct {
	key           challengeKey
	authorization *oauth2.AuthorizationRequest
}

func (challenge *Challenge) GetKey() string {
	return string(challenge.key)
}

func (challenge *Challenge) GetAuthorizationState() *oauth2.AuthorizationRequest {
	return challenge.authorization
}

func (challenge *Challenge) BindAuthorizationState(request *oauth2.AuthorizationRequest) {
	challenge.authorization = request
}
