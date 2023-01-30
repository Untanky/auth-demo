package utils

import "math/rand"

const challengeAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

func RandString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = challengeAlphabet[rand.Intn(len(challengeAlphabet))]
	}
	return string(b)
}
