package challenge

import (
	"github.com/Untanky/iam-auth/core"
	"github.com/Untanky/iam-auth/oauth2"
	"github.com/Untanky/iam-auth/webauthn"
)

type state interface {
	GetKey() string
}

type AuthorizationState interface {
	state
	GetAuthorizationState() *oauth2.AuthorizationRequest
	BindAuthorizationState(request *oauth2.AuthorizationRequest)
}

type LoginState interface {
	state
	GetLoginState() *webauthn.LoginResponse
	BindLoginState(request *webauthn.LoginResponse)
}

type RegisterState interface {
	state
	GetRegisterState() *webauthn.RegisterResponse
	BindRegisterState(request *webauthn.RegisterResponse)
}

type authorizationStateCache[bar AuthorizationState] struct {
	repo core.Repository[string, bar]
}

func (test *authorizationStateCache[bar]) Get(key string) (*oauth2.AuthorizationRequest, error) {
	state, err := test.repo.FindByID(key)
	if err != nil {
		return nil, err
	}

	return state.GetAuthorizationState(), nil
}

func (test *authorizationStateCache[bar]) SetWithoutKey(value *oauth2.AuthorizationRequest) (string, error) {
	state, err := test.repo.CreateEmpty()
	if err != nil {
		return "", err
	}
	state.BindAuthorizationState(value)
	err = test.repo.Update(state)
	return state.GetKey(), err
}

func (test *authorizationStateCache[bar]) Set(key string, value *oauth2.AuthorizationRequest) error {
	state, err := test.repo.FindByID(key)
	if err != nil {
		return err
	}
	state.BindAuthorizationState(value)
	return test.repo.Update(state)
}

func (test *authorizationStateCache[bar]) Delete(key string) error {
	return test.repo.DeleteByID(key)
}

func RepoToAuthorizationState[bar AuthorizationState](repo core.Repository[string, bar]) core.Cache[string, *oauth2.AuthorizationRequest] {
	return &authorizationStateCache[bar]{
		repo: repo,
	}
}

type loginStateCache[bar LoginState] struct {
	repo core.Repository[string, bar]
}

func (test *loginStateCache[bar]) Get(key string) (*webauthn.LoginResponse, error) {
	state, err := test.repo.FindByID(key)
	if err != nil {
		return nil, err
	}

	return state.GetLoginState(), nil
}

func (test *loginStateCache[bar]) SetWithoutKey(value *webauthn.LoginResponse) (string, error) {
	state, err := test.repo.CreateEmpty()
	if err != nil {
		return "", err
	}
	state.BindLoginState(value)
	err = test.repo.Update(state)
	return state.GetKey(), err
}

func (test *loginStateCache[bar]) Set(key string, value *webauthn.LoginResponse) error {
	state, err := test.repo.FindByID(key)
	if err != nil {
		return err
	}
	state.BindLoginState(value)
	return test.repo.Update(state)
}

func (test *loginStateCache[bar]) Delete(key string) error {
	return test.repo.DeleteByID(key)
}

func RepoToLoginState[bar LoginState](repo core.Repository[string, bar]) core.Cache[string, *webauthn.LoginResponse] {
	return &loginStateCache[bar]{
		repo: repo,
	}
}

type registerStateCache[bar RegisterState] struct {
	repo core.Repository[string, bar]
}

func (test *registerStateCache[bar]) Get(key string) (*webauthn.RegisterResponse, error) {
	state, err := test.repo.FindByID(key)

	if err != nil {
		return nil, err
	}

	return state.GetRegisterState(), nil
}

func (test *registerStateCache[bar]) SetWithoutKey(value *webauthn.RegisterResponse) (string, error) {
	state, err := test.repo.CreateEmpty()
	if err != nil {
		return "", err
	}
	state.BindRegisterState(value)
	err = test.repo.Update(state)
	return state.GetKey(), err
}

func (test *registerStateCache[bar]) Set(key string, value *webauthn.RegisterResponse) error {
	state, err := test.repo.FindByID(key)
	if err != nil {
		return err
	}
	state.BindRegisterState(value)
	return test.repo.Update(state)
}

func (test *registerStateCache[bar]) Delete(key string) error {
	return test.repo.DeleteByID(key)
}

func RepoToRegisterState[bar RegisterState](repo core.Repository[string, bar]) core.Cache[string, *webauthn.RegisterResponse] {
	return &registerStateCache[bar]{
		repo: repo,
	}
}
