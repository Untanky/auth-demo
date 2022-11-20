package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"reflect"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// URLEncodedBase64 represents a byte slice holding URL-encoded base64 data.
// When fields of this type are unmarshaled from JSON, the data is base64
// decoded into a byte slice.
type URLEncodedBase64 []byte

// UnmarshalJSON base64 decodes a URL-encoded value, storing the result in the
// provided byte slice.
func (dest *URLEncodedBase64) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		return nil
	}

	// Trim the leading spaces
	data = bytes.Trim(data, "\"")
	out := make([]byte, base64.RawURLEncoding.DecodedLen(len(data)))
	n, err := base64.RawURLEncoding.Decode(out, data)
	if err != nil {
		return err
	}

	v := reflect.ValueOf(dest).Elem()
	v.SetBytes(out[:n])
	return nil
}

// MarshalJSON base64 encodes a non URL-encoded value, storing the result in the
// provided byte slice.
func (data URLEncodedBase64) MarshalJSON() ([]byte, error) {
	if data == nil {
		return []byte("null"), nil
	}
	return []byte(`"` + base64.RawURLEncoding.EncodeToString(data) + `"`), nil
}

const nestedLevelsAllowed = 4

type AuthenticateRequest struct {
	Identifier string `json:"identifier"`
}

type RelyingPartyResponse struct {
	Name string `json:"name"`
	Id   string `json:"id"`
}

type UserReponse struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type PublicKeyCredentialsResponse struct {
	Algorithm int32  `json:"alg"`
	Type      string `json:"type"`
}

type AuthenticatorSelectionResponse struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment"`
}

type AuthenticateResponse struct {
	Challenge                      string                         `json:"challenge"`
	RelyingParty                   RelyingPartyResponse           `json:"rp"`
	User                           UserReponse                    `json:"user"`
	PublicKeyCredentialsParameters []PublicKeyCredentialsResponse `json:"pubKeyCredParams"`
	AuthenticatorSelection         AuthenticatorSelectionResponse `json:"authenticatorSelection"`
	Timeout                        int32                          `json:"timeout"`
	Attestation                    string                         `json:"attestation"`
}

type CredentialReponse struct {
	AttestationObject URLEncodedBase64 `json:"attestationObject"`
	ClientDataJSON    URLEncodedBase64 `json:"clientDataJSON"`
}

type RegisterRequest struct {
	Id      string            `json:"id"`
	Type    string            `json:"type"`
	RawId   string            `json:"rawId"`
	Reponse CredentialReponse `json:"response"`
}

type RegisterResponse struct {
	Challenge string
}

type ClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

type PackedAttestationStatement struct {
	Algorithm   int    `cbor:"alg"`
	Signature   []byte `cbor:"sig"`
	Certificate []byte `cbor:"x5c,omitifempty"`
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func main() {
	challengeMap := map[string]AuthenticateResponse{}
	knownIdentifiers := []string{}

	relyingParty := RelyingPartyResponse{Id: "localhost", Name: "IAM Auth"}
	authenticatorSelection := AuthenticatorSelectionResponse{AuthenticatorAttachment: "both"}
	publicKeyCredentialsParams := []PublicKeyCredentialsResponse{{Algorithm: -7, Type: "public-key"}}

	router := gin.Default()

	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:5501"}
	config.ExposeHeaders = []string{"Next-Step"}

	router.Use(cors.New(config))

	router.POST("/authenticate", func(c *gin.Context) {
		body := AuthenticateRequest{}
		if err := c.ShouldBind(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "could not parse body",
			})
			fmt.Println(err)
			return
		}

		var response AuthenticateResponse

		isIdentifierKnown := false
		for i := 0; i < len(knownIdentifiers); i++ {
			if body.Identifier == knownIdentifiers[i] {
				isIdentifierKnown = true
			}
		}

		if isIdentifierKnown {
			c.Header("Next-Step", "login")
		} else {
			c.Header("Next-Step", "register")
			response = AuthenticateResponse{
				Challenge:                      randStringBytes(20),
				RelyingParty:                   relyingParty,
				User:                           UserReponse{Id: "abc", Name: body.Identifier, DisplayName: "Lukas"},
				PublicKeyCredentialsParameters: publicKeyCredentialsParams,
				AuthenticatorSelection:         authenticatorSelection,
				Timeout:                        60000,
				Attestation:                    "direct",
			}
		}

		challengeMap[response.Challenge] = response

		c.JSON(http.StatusOK, response)
	})

	router.POST("/register", func(c *gin.Context) {
		body := RegisterRequest{}
		err := json.NewDecoder(c.Request.Body).Decode(&body)

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "could not parse body",
			})
			fmt.Println("Error", err)
			return
		}

		clientData := ClientData{}
		json.Unmarshal([]byte(body.Reponse.ClientDataJSON), &clientData)

		// Implementation of https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
		challenge, _ := base64.RawStdEncoding.DecodeString(clientData.Challenge)
		_, ok := challengeMap[string(challenge)]

		if !ok || clientData.Type != "webauthn.create" || !strings.Contains(clientData.Origin, "localhost") {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "client data incorrect",
			})
			fmt.Println("client data incorrect", clientData)
			return
		}

		hash := sha256.New()
		hash.Write([]byte(body.Reponse.ClientDataJSON))
		fmt.Printf("Hash: %x\n", hash.Sum(nil))

		type attestationObject struct {
			AuthnData []byte          `cbor:"authData"`
			Fmt       string          `cbor:"fmt"`
			AttStmt   cbor.RawMessage `cbor:"attStmt"`
		}
		var attstObj attestationObject
		if err := cbor.Unmarshal(body.Reponse.AttestationObject, &attstObj); err != nil {
			fmt.Println("error:", err)
		}

		if _, err := cbor.Marshal(attstObj); err != nil {
			fmt.Println("error:", err)
		}

		// TODO: Check attstObj.AuthnData
		// TODO: Check flags
		// TODO: Check algorithm

		// TODO: Implemented https://w3c.github.io/webauthn/#sctn-fido-u2f-attestation

		var attStmt PackedAttestationStatement
		err = cbor.Unmarshal([]byte(attstObj.AttStmt), &attStmt)
		if err != nil {
			fmt.Println(err)
		}

		fmt.Println("AttStmt", string(attStmt.Signature))
		fmt.Println("AuthData", string(attstObj.AuthnData))
		fmt.Println("Fmt", string(attstObj.Fmt))

		c.JSON(http.StatusOK, nil)
	})

	router.POST("/login", func(c *gin.Context) {
		body := AuthenticateRequest{}
		if err := c.ShouldBind(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "could not parse body",
			})
			fmt.Println(err)
			return
		}

		// Implementation of https://w3c.github.io/webauthn/#sctn-verifying-assertion

		c.JSON(http.StatusOK, nil)
	})

	router.Run()
}
