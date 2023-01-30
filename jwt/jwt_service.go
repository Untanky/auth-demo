package jwt

import (
	"errors"

	"github.com/Untanky/iam-auth/secret"
)

type JwtService[Type secret.SecretType] struct {
	Method signingMethod
	Secret secret.Secret[Type]
}

func (service *JwtService[Type]) Init(method signingMethod, secret secret.Secret[Type]) {
	service.Method = method
	service.Secret = secret
}

func (service *JwtService[Type]) Create(data map[string]interface{}) (Jwt, error) {
	if str, ok := any(service.Secret.GetSecret()).(secret.SecretString); ok == true {
		return CreateJwt(service.Method, data, string(str))
	}

	if pair, ok := any(service.Secret.GetSecret()).(secret.KeyPair); ok == true {
		return CreateJwt(service.Method, data, string(pair.PrivateKey))
	}

	return Jwt(""), errors.New("unknown secret type")
}
