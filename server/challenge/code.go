package challenge

import (
	"github.com/Untanky/iam-auth/oauth2"
)

type codeKey string

func generateCodeKey() codeKey {
	return codeKey(randStringBytes(12))
}

// A stateful authorization challenge
type code struct {
	key           challengeKey
	authorization *oauth2.AuthorizationRequest
}

func (code *code) BindAuthorizationState(request *oauth2.AuthorizationRequest) {
	code.authorization = request
}

type CodeRepository interface {
	FindByKey(key codeKey) (*challenge, error)
	Create() (*challenge, error)
	Update(*challenge) error
	Delete(*challenge) error
	DeleteByKey(key codeKey) error
}

func AuthorizationStateFromCodeRepo(repo CodeRepository) oauth2.AuthorizationState {
    return &codeAuthorizationState{
        repo: repo,
    }
}

type codeAuthorizationState struct {
	repo CodeRepository
}

func (state *codeAuthorizationState) Get(key string) (*oauth2.AuthorizationRequest, error) {
	challenge, err := state.repo.FindByKey(codeKey(key))
	if err != nil {
		return nil, err
	}

	return challenge.authorization, nil
}

func (state *codeAuthorizationState) Set(request *oauth2.AuthorizationRequest) (string, error) {
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
