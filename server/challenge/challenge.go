package challenge

import (
	"math/rand"

	"github.com/Untanky/iam-auth/oauth2"
)

const challengeAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

type challengeKey string

func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = challengeAlphabet[rand.Intn(len(challengeAlphabet))]
	}
	return string(b)
}

func generateChallengeKey() challengeKey {
	return challengeKey(randStringBytes(32))
}

// A stateful authorization challenge
type challenge struct {
	key           challengeKey
	authorization *oauth2.AuthorizationRequest
}

func (challenge *challenge) BindAuthorizationState(request *oauth2.AuthorizationRequest) {
	challenge.authorization = request
}

type ChallengeRepository interface {
	FindChallengeByKey(key challengeKey) (*challenge, error)
	CreateChallenge() (*challenge, error)
	UpdateChallenge(*challenge) error
	DeleteChallenge(*challenge) error
	DeleteChallengeByKey(key challengeKey) error
}

func GetAuthorizationStateFrom(repo ChallengeRepository) oauth2.GetAuthorizationState {
	return func(key string) (*oauth2.AuthorizationRequest, error) {
		challenge, err := repo.FindChallengeByKey(challengeKey(key))

		if err != nil {
			return nil, err
		}
		return challenge.authorization, nil
	}
}
