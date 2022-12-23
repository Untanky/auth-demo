package challenge_test

import (
	"testing"

	"github.com/Untanky/iam-auth/challenge"
)

func TestGenerateChallengeKey(t *testing.T) {
	a := challenge.GenerateChallengeKey()
	b := challenge.GenerateChallengeKey()

	if a == b {
		t.Logf("challenges are equal (%s = %s)", a, b)
		t.Fail()
	}
}
