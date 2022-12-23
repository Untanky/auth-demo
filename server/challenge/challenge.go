package challenge

import (
	"math/rand"
)

const challengeAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = challengeAlphabet[rand.Intn(len(challengeAlphabet))]
	}
	return string(b)
}

func GenerateChallengeKey() string {
	return randStringBytes(32)
}

// A stateful authorization challenge
type Challenge struct {
	Value string
}