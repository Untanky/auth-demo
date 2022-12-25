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
	FindByKey(key challengeKey) (*challenge, error)
	Create() (*challenge, error)
	Update(*challenge) error
	Delete(*challenge) error
	DeleteByKey(key challengeKey) error
}

func AuthorizationStateFromChallengeRepo(repo ChallengeRepository) oauth2.AuthorizationState {
    return &challengeAuthorizationState{
        repo: repo,
    }
}

type challengeAuthorizationState struct {
	repo ChallengeRepository
}

func (state *challengeAuthorizationState) Get(key string) (*oauth2.AuthorizationRequest, error) {
	challenge, err := state.repo.FindByKey(challengeKey(key))
	if err != nil {
		return nil, err
	}

	return challenge.authorization, nil
}

func (state *challengeAuthorizationState) Set(request *oauth2.AuthorizationRequest) (string, error) {
	challenge, err := state.repo.Create()
	if err != nil {
		return "", err
	}

	challenge.authorization = request

	err = state.repo.Update(challenge)
	if err != nil {
		return "", err
	}

	return string(challenge.key), nil
}
