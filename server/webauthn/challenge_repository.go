package webauthn

import (
	"errors"
	"fmt"
	"math/rand"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func GenerateChallenge() string {
	return randStringBytes(32)
}

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
	Challenges map[string]interface{}
}

func (repo *InMemoryChallengeRepository) FindByValue(value string) (*Challenge, error) {
	authenticateResponse, ok := repo.Challenges[value]
	if !ok {
		return nil, fmt.Errorf("Could not find challenge '%s'", value)
	}

	r, ok := authenticateResponse.(RegisterResponse)
	if ok {
		return &Challenge{
			Value:    r.Challenge,
			Response: authenticateResponse,
		}, nil
	}

	l, ok := authenticateResponse.(LoginResponse)
	if ok {
		return &Challenge{
			Value:    l.Challenge,
			Response: authenticateResponse,
		}, nil
	}

	return nil, errors.New("Not found")
}

func (repo *InMemoryChallengeRepository) Create(challenge *Challenge) error {
	repo.Challenges[challenge.Value] = challenge.Response
	return nil
}

func (repo *InMemoryChallengeRepository) DeleteByValue(value string) error {
	delete(repo.Challenges, value)
	return nil
}
