package main

import "fmt"

type Challenge struct {
	Value    string
	Response interface{}
}

type ChallengeRepository interface {
	FindByValue(value string) (*Challenge, error)
	Create(user *Challenge) error
	DeleteByValue(value string) error
}

type InMemoryChallengeRepository struct {
	challenges map[string]interface{}
}

func (repo *InMemoryChallengeRepository) FindByValue(value string) (*Challenge, error) {
	authenticateResponse, ok := repo.challenges[value]
	if !ok {
		return nil, fmt.Errorf("Could not find challenge '%s'", value)
	}

    r := authenticateResponse.(RegisterResponse)

	return &Challenge{
		Value:    r.Challenge,
		Response: authenticateResponse,
	}, nil
}

func (repo *InMemoryChallengeRepository) Create(challenge *Challenge) error {
	repo.challenges[challenge.Value] = challenge.Response
	return nil
}

func (repo *InMemoryChallengeRepository) DeleteByValue(value string) error {
	delete(repo.challenges, value)
	return nil
}
