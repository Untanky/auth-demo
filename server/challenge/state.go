package challenge

import (
	"github.com/Untanky/iam-auth/oauth2"
	"github.com/Untanky/iam-auth/utils"
)

type AuthorizationState interface {
	GetKey() string
	GetAuthorizationState() *oauth2.AuthorizationRequest
	BindAuthorizationState(request *oauth2.AuthorizationRequest)
}

type foo[bar AuthorizationState] struct {
    repo utils.Repository[string, bar]
}

func (test *foo[bar]) Get(key string) (*oauth2.AuthorizationRequest, error) {
	state, err := test.repo.FindByID(key)
	if err != nil {
		return nil, err
	}

	return state.GetAuthorizationState(), nil
}

func (test *foo[bar]) SetWithoutKey(value *oauth2.AuthorizationRequest) (string, error) {
	state, err := test.repo.CreateEmpty()
	if err != nil {
		return "", err
	}
	state.BindAuthorizationState(value)
	err = test.repo.Update(state)
	return state.GetKey(), err
}

func (test *foo[bar]) Set(key string, value *oauth2.AuthorizationRequest) error {
	state, err := test.repo.FindByID(key)
	if err != nil {
		return err
	}
	state.BindAuthorizationState(value)
	return test.repo.Update(state)
}

func (test *foo[bar]) Delete(key string) error {
	return test.repo.DeleteByKey(key)
}

func RepoToAuthorizationState[bar AuthorizationState](repo utils.Repository[string, bar]) utils.Cache[string, *oauth2.AuthorizationRequest] {
	return &foo[bar]{
		repo: repo,
	}
}
