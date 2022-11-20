package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"reflect"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

const (
	minAuthDataLength     = 37
	minAttestedAuthLength = 55

	// https://w3c.github.io/webauthn/#attested-credential-data
	maxCredentialIDLength = 1023
)

const (
	// FlagUserPresent Bit 00000001 in the byte sequence. Tells us if user is present
	FlagUserPresent AuthenticatorFlags = 1 << iota // Referred to as UP
	_                                              // Reserved
	// FlagUserVerified Bit 00000100 in the byte sequence. Tells us if user is verified
	// by the authenticator using a biometric or PIN
	FlagUserVerified // Referred to as UV
	_                // Reserved
	_                // Reserved
	_                // Reserved
	// FlagAttestedCredentialData Bit 01000000 in the byte sequence. Indicates whether
	// the authenticator added attested credential data.
	FlagAttestedCredentialData // Referred to as AT
	// FlagHasExtension Bit 10000000 in the byte sequence. Indicates if the authenticator data has extensions.
	FlagHasExtensions //  Referred to as ED
)

// UserPresent returns if the UP flag was set
func (flag AuthenticatorFlags) UserPresent() bool {
	return (flag & FlagUserPresent) == FlagUserPresent
}

// UserVerified returns if the UV flag was set
func (flag AuthenticatorFlags) UserVerified() bool {
	return (flag & FlagUserVerified) == FlagUserVerified
}

// HasAttestedCredentialData returns if the AT flag was set
func (flag AuthenticatorFlags) HasAttestedCredentialData() bool {
	return (flag & FlagAttestedCredentialData) == FlagAttestedCredentialData
}

// HasExtensions returns if the ED flag was set
func (flag AuthenticatorFlags) HasExtensions() bool {
	return (flag & FlagHasExtensions) == FlagHasExtensions
}

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

// AuthenticatorFlags A byte of information returned during during ceremonies in the
// authenticatorData that contains bits that give us information about the
// whether the user was present and/or verified during authentication, and whether
// there is attestation or extension data present. Bit 0 is the least significant bit.
type AuthenticatorFlags byte

// AuthenticatorData From §6.1 of the spec.
// The authenticator data structure encodes contextual bindings made by the authenticator. These bindings
// are controlled by the authenticator itself, and derive their trust from the WebAuthn Relying Party's
// assessment of the security properties of the authenticator. In one extreme case, the authenticator
// may be embedded in the client, and its bindings may be no more trustworthy than the client data.
// At the other extreme, the authenticator may be a discrete entity with high-security hardware and
// software, connected to the client over a secure channel. In both cases, the Relying Party receives
// the authenticator data in the same format, and uses its knowledge of the authenticator to make
// trust decisions.
//
// The authenticator data, at least during attestation, contains the Public Key that the RP stores
// and will associate with the user attempting to register.
type AuthenticatorData struct {
	RPIDHash []byte                 `json:"rpid"`
	Flags    AuthenticatorFlags     `json:"flags"`
	Counter  uint32                 `json:"sign_count"`
	AttData  AttestedCredentialData `json:"att_data"`
	ExtData  []byte                 `json:"ext_data"`
}

type AttestedCredentialData struct {
	AAGUID       []byte `json:"aaguid"`
	CredentialID []byte `json:"credential_id"`
	// The raw credential public key bytes received from the attestation data
	CredentialPublicKey []byte `json:"public_key"`
}

// Unmarshal will take the raw Authenticator Data and marshalls it into AuthenticatorData for further validation.
// The authenticator data has a compact but extensible encoding. This is desired since authenticators can be
// devices with limited capabilities and low power requirements, with much simpler software stacks than the client platform.
// The authenticator data structure is a byte array of 37 bytes or more, and is laid out in this table:
// https://www.w3.org/TR/webauthn/#table-authData
func (a *AuthenticatorData) Unmarshal(rawAuthData []byte) error {
	if minAuthDataLength > len(rawAuthData) {
		err := errors.New("Authenticator data length too short")
		// info := fmt.Sprintf("Expected data greater than %d bytes. Got %d bytes\n", minAuthDataLength, len(rawAuthData))
		return err
	}

	a.RPIDHash = rawAuthData[:32]
	a.Flags = AuthenticatorFlags(rawAuthData[32])
	a.Counter = binary.BigEndian.Uint32(rawAuthData[33:37])

	remaining := len(rawAuthData) - minAuthDataLength

	if a.Flags.HasAttestedCredentialData() {
		if len(rawAuthData) > minAttestedAuthLength {
			validError := a.unmarshalAttestedData(rawAuthData)
			if validError != nil {
				return validError
			}
			attDataLen := len(a.AttData.AAGUID) + 2 + len(a.AttData.CredentialID) + len(a.AttData.CredentialPublicKey)
			remaining = remaining - attDataLen
		} else {
			return errors.New("Attested credential flag set but data is missing")
		}
	} else {
		if !a.Flags.HasExtensions() && len(rawAuthData) != 37 {
			return errors.New("Attested credential flag not set")
		}
	}

	if a.Flags.HasExtensions() {
		if remaining != 0 {
			a.ExtData = rawAuthData[len(rawAuthData)-remaining:]
			remaining -= len(a.ExtData)
		} else {
			return errors.New("Extensions flag set but extensions data is missing")
		}
	}

	if remaining != 0 {
		return errors.New("Leftover bytes decoding AuthenticatorData")
	}

	return nil
}

// If Attestation Data is present, unmarshall that into the appropriate public key structure
func (a *AuthenticatorData) unmarshalAttestedData(rawAuthData []byte) error {
	a.AttData.AAGUID = rawAuthData[37:53]
	idLength := binary.BigEndian.Uint16(rawAuthData[53:55])
	if len(rawAuthData) < int(55+idLength) {
		return errors.New("Authenticator attestation data length too short")
	}
	if idLength > maxCredentialIDLength {
		return errors.New("Authenticator attestation data credential id length too long")
	}
	a.AttData.CredentialID = rawAuthData[55 : 55+idLength]
	a.AttData.CredentialPublicKey = unmarshalCredentialPublicKey(rawAuthData[55+idLength:])
	return nil
}

// Unmarshall the credential's Public Key into CBOR encoding
func unmarshalCredentialPublicKey(keyBytes []byte) []byte {
	var m interface{}
	cbor.Unmarshal(keyBytes, &m)
	rawBytes, _ := cbor.Marshal(m)
	return rawBytes
}

// ResidentKeyRequired - Require that the key be private key resident to the client device
func ResidentKeyRequired() *bool {
	required := true
	return &required
}

// ResidentKeyUnrequired - Do not require that the private key be resident to the client device.
func ResidentKeyUnrequired() *bool {
	required := false
	return &required
}

// Verify on AuthenticatorData handles Steps 9 through 12 for Registration
// and Steps 11 through 14 for Assertion.
func (a *AuthenticatorData) Verify(rpIdHash, appIDHash []byte, userVerificationRequired bool) error {

	// Registration Step 9 & Assertion Step 11
	// Verify that the RP ID hash in authData is indeed the SHA-256
	// hash of the RP ID expected by the RP.
	if !bytes.Equal(a.RPIDHash[:], rpIdHash) && !bytes.Equal(a.RPIDHash[:], appIDHash) {
		return errors.New(fmt.Sprintf("RP Hash mismatch. Expected %x and Received %x\n", a.RPIDHash, rpIdHash))
	}

	// Registration Step 10 & Assertion Step 12
	// Verify that the User Present bit of the flags in authData is set.
	if !a.Flags.UserPresent() {
		return errors.New(fmt.Sprintln("User presence flag not set by authenticator"))
	}

	// Registration Step 11 & Assertion Step 13
	// If user verification is required for this assertion, verify that
	// the User Verified bit of the flags in authData is set.
	if userVerificationRequired && !a.Flags.UserVerified() {
		return errors.New(fmt.Sprintln("User verification required but flag not set by authenticator"))
	}

	// Registration Step 12 & Assertion Step 14
	// Verify that the values of the client extension outputs in clientExtensionResults
	// and the authenticator extension outputs in the extensions in authData are as
	// expected, considering the client extension input values that were given as the
	// extensions option in the create() call. In particular, any extension identifier
	// values in the clientExtensionResults and the extensions in authData MUST be also be
	// present as extension identifier values in the extensions member of options, i.e., no
	// extensions are present that were not requested. In the general case, the meaning
	// of "are as expected" is specific to the Relying Party and which extensions are in use.

	// This is not yet fully implemented by the spec or by browsers

	return nil
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

		var authData AuthenticatorData
		err = authData.Unmarshal(attstObj.AuthnData)
		if err != nil {
			fmt.Println(err)
		}

		key, err := ParsePublicKey(authData.AttData.CredentialPublicKey)

		// TODO: Check attstObj.AuthnData
		// TODO: Check flags
		// TODO: Check algorithm

		// TODO: Implemented https://w3c.github.io/webauthn/#sctn-fido-u2f-attestation

		var attStmt PackedAttestationStatement
		err = cbor.Unmarshal([]byte(attstObj.AttStmt), &attStmt)
		if err != nil {
			fmt.Println(err)
		}

		if key.GetAlgorithm() != attStmt.Algorithm {
			fmt.Println("Algorithm does not match", key.GetAlgorithm(), attStmt.Algorithm)
			return
		}

		verificationData := append(attstObj.AuthnData, hash.Sum(nil)...)

		ok, err = key.Verify(verificationData, attStmt.Signature)
		if err != nil {
			fmt.Println(err)
			return
		}
		if !ok {
			fmt.Println("Something went wrong")
			return
		}

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
