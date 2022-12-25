package secret_test

import (
	"testing"

	. "github.com/Untanky/iam-auth/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type SecretTestSuite struct {
	suite.Suite
}

func (suite *SecretTestSuite) SetupTest() {
}

func (suite *SecretTestSuite) TestStringSecret_GetSecret() {
	value := "secret_value"
	secret := NewSecretValue(value)

	assert.NotNil(suite.T(), secret)
	assert.Equal(suite.T(), value, string(secret.GetSecret()))
}

func (suite *SecretTestSuite) TestPairSecret_GetSecret() {
	value := KeyPair{
		PrivateKey: "private",
		PublicKey:  "public",
	}
	secret := NewSecretPair(value)

	assert.NotNil(suite.T(), secret)
	assert.Equal(suite.T(), value, secret.GetSecret())
}

func (suite *SecretTestSuite) TestRotateSecret() {
	value := "secret_value"
	nextValue := "new_secret_value"
	secret := NewRotatingSecret(NewSecretValue(value))

	actual := secret.GetSecret()
	assert.NotNil(suite.T(), secret)
	assert.Equal(suite.T(), value, string(actual))

	secret.Rotate(NewSecretValue(nextValue))

	actual = secret.GetSecret()
	assert.NotEqual(suite.T(), value, actual)
	assert.Equal(suite.T(), nextValue, string(actual))
}

func TestSecrets(t *testing.T) {
	suite.Run(t, new(SecretTestSuite))
}
