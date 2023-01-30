package jwt

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

type signingMethod string

const (
	HS256 signingMethod = "HS256"
	HS384 signingMethod = "HS384"
	HS512 signingMethod = "HS512"
	RS256 signingMethod = "RS256"
	RS384 signingMethod = "RS384"
	RS512 signingMethod = "RS512"
	ES256 signingMethod = "ES256"
	ES384 signingMethod = "ES384"
	ES512 signingMethod = "ES512"
	PS256 signingMethod = "PS256"
	PS384 signingMethod = "PS384"
	PS512 signingMethod = "PS512"
)

var SigningMethods = []signingMethod{HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512}

func readBase64Json(base64Json string) (map[string]interface{}, error) {
	utf8Json, err := base64.RawStdEncoding.DecodeString(base64Json)
	if err != nil {
		return map[string]interface{}{}, errors.New("cannot convert from base64")
	}

	var object map[string]interface{}
	err = json.Unmarshal(utf8Json, &object)
	if err != nil {
		return map[string]interface{}{}, errors.New("cannot unmarschal json")
	}

	return object, nil
}

type Jwt string

type header struct {
	Alg string
	Typ string
}

type payload map[string]interface{}

func (jwt *Jwt) Header() (header, error) {
	splitJwt := strings.SplitN(string(*jwt), ".", 3)

	if len(splitJwt) <= 3 {
		errors.New("jwt malformed")
	}

	headerMap, err := readBase64Json(splitJwt[0])
	if err != nil {
		return header{}, err
	}

	alg, algOk := headerMap["alg"].(string)
	typ, typOk := headerMap["typ"].(string)
	if !algOk || !typOk {
		return header{}, errors.New("invalid header")
	}

	return header{
		Alg: alg,
		Typ: typ,
	}, nil
}

func (jwt *Jwt) Payload() (payload, error) {
	splitJwt := strings.SplitN(string(*jwt), ".", 3)

	if len(splitJwt) <= 3 {
		errors.New("jwt malformed")
	}

	payloadMap, err := readBase64Json(splitJwt[1])
	if err != nil {
		return payload{}, err
	}

	return payload(payloadMap), nil
}

func (token *Jwt) Validate(key string) error {
	_, err := jwt.Parse(string(*token), func(t *jwt.Token) (interface{}, error) {
		switch t.Method.(type) {
		case *jwt.SigningMethodHMAC:
			return []byte(key), nil
		case *jwt.SigningMethodRSA:
			return decodePublicPem(key)
		case *jwt.SigningMethodECDSA:
			return decodePublicPem(key)
		case *jwt.SigningMethodRSAPSS:
			return decodePublicPem(key)
		default:
			return nil, errors.New("unknown signing method")
		}

	})

	return err
}

func decodePublicPem(pemString string) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse DER encoded public key: " + err.Error())
	}
	return pub, nil
}

func decodePrivatePem(pemString string) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the private key")
	}

	private, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse DER encoded private key: " + err.Error())
	}
	return private, nil
}

func CreateJwt(method signingMethod, data payload, key string) (Jwt, error) {
	signing := convertSigningMethod(method)
	token := jwt.NewWithClaims(signing, jwt.MapClaims(data))
	decodedKey, err := decodeKey(method, key)
	fmt.Println(err)
	tokenString, err := token.SignedString(decodedKey)

	fmt.Println(err)

	return Jwt(tokenString), err
}

func convertSigningMethod(method signingMethod) jwt.SigningMethod {
	switch method {
	case HS256:
		return jwt.SigningMethodHS256
	case HS384:
		return jwt.SigningMethodHS384
	case HS512:
		return jwt.SigningMethodHS512
	case RS256:
		return jwt.SigningMethodRS256
	case RS384:
		return jwt.SigningMethodRS384
	case RS512:
		return jwt.SigningMethodRS512
	case ES256:
		return jwt.SigningMethodES256
	case ES384:
		return jwt.SigningMethodES384
	case ES512:
		return jwt.SigningMethodES512
	case PS256:
		return jwt.SigningMethodPS256
	case PS384:
		return jwt.SigningMethodPS384
	case PS512:
		return jwt.SigningMethodPS512
	default:
		return nil
	}
}

func decodeKey(method signingMethod, key string) (interface{}, error) {
	switch method {
	case HS256, HS384, HS512:
		return []byte(key), nil
	case RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512:
		return decodePrivatePem(key)
	default:
		return nil, errors.New("unknown signing method")
	}
}
