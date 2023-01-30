package keys

import (
	"crypto"
	"errors"
	"hash"

	"github.com/fxamacker/cbor/v2"
)

// COSEAlgorithmIdentifier From §5.10.5. A number identifying a cryptographic algorithm. The algorithm
// identifiers SHOULD be values registered in the IANA COSE Algorithms registry
// [https://www.w3.org/TR/webauthn/#biblio-iana-cose-algs-reg], for instance, -7 for "ES256"
//
//	and -257 for "RS256".
type COSEAlgorithmIdentifier int

const (
	// AlgES256 ECDSA with SHA-256
	AlgES256 COSEAlgorithmIdentifier = -7
	// AlgES384 ECDSA with SHA-384
	AlgES384 COSEAlgorithmIdentifier = -35
	// AlgES512 ECDSA with SHA-512
	AlgES512 COSEAlgorithmIdentifier = -36
	// AlgRS1 RSASSA-PKCS1-v1_5 with SHA-1
	AlgRS1 COSEAlgorithmIdentifier = -65535
	// AlgRS256 RSASSA-PKCS1-v1_5 with SHA-256
	AlgRS256 COSEAlgorithmIdentifier = -257
	// AlgRS384 RSASSA-PKCS1-v1_5 with SHA-384
	AlgRS384 COSEAlgorithmIdentifier = -258
	// AlgRS512 RSASSA-PKCS1-v1_5 with SHA-512
	AlgRS512 COSEAlgorithmIdentifier = -259
	// AlgPS256 RSASSA-PSS with SHA-256
	AlgPS256 COSEAlgorithmIdentifier = -37
	// AlgPS384 RSASSA-PSS with SHA-384
	AlgPS384 COSEAlgorithmIdentifier = -38
	// AlgPS512 RSASSA-PSS with SHA-512
	AlgPS512 COSEAlgorithmIdentifier = -39
	// AlgEdDSA EdDSA
	AlgEdDSA COSEAlgorithmIdentifier = -8
)

// Algorithm enumerations used for
type SignatureAlgorithm int

const (
	UnknownSignatureAlgorithm SignatureAlgorithm = iota
	MD2WithRSA
	MD5WithRSA
	SHA1WithRSA
	SHA256WithRSA
	SHA384WithRSA
	SHA512WithRSA
	DSAWithSHA1
	DSAWithSHA256
	ECDSAWithSHA1
	ECDSAWithSHA256
	ECDSAWithSHA384
	ECDSAWithSHA512
	SHA256WithRSAPSS
	SHA384WithRSAPSS
	SHA512WithRSAPSS
)

var SignatureAlgorithmDetails = []struct {
	algo    SignatureAlgorithm
	coseAlg COSEAlgorithmIdentifier
	name    string
	hasher  func() hash.Hash
}{
	{SHA1WithRSA, AlgRS1, "SHA1-RSA", crypto.SHA1.New},
	{SHA256WithRSA, AlgRS256, "SHA256-RSA", crypto.SHA256.New},
	{SHA384WithRSA, AlgRS384, "SHA384-RSA", crypto.SHA384.New},
	{SHA512WithRSA, AlgRS512, "SHA512-RSA", crypto.SHA512.New},
	{SHA256WithRSAPSS, AlgPS256, "SHA256-RSAPSS", crypto.SHA256.New},
	{SHA384WithRSAPSS, AlgPS384, "SHA384-RSAPSS", crypto.SHA384.New},
	{SHA512WithRSAPSS, AlgPS512, "SHA512-RSAPSS", crypto.SHA512.New},
	{ECDSAWithSHA256, AlgES256, "ECDSA-SHA256", crypto.SHA256.New},
	{ECDSAWithSHA384, AlgES384, "ECDSA-SHA384", crypto.SHA384.New},
	{ECDSAWithSHA512, AlgES512, "ECDSA-SHA512", crypto.SHA512.New},
	{UnknownSignatureAlgorithm, AlgEdDSA, "EdDSA", crypto.SHA512.New},
}

// Return the Hashing interface to be used for a given COSE Algorithm
func HasherFromCOSEAlg(coseAlg COSEAlgorithmIdentifier) func() hash.Hash {
	for _, details := range SignatureAlgorithmDetails {
		if details.coseAlg == coseAlg {
			return details.hasher
		}
	}
	// default to SHA256?  Why not.
	return crypto.SHA256.New
}

type PublicKey interface {
	Verify([]byte, []byte) (bool, error)
	GetAlgorithm() int
}

// PublicKeyData The public key portion of a RelyingParty Party-specific credential key pair, generated
// by an authenticator and returned to a RelyingParty Party at registration time. We unpack this object
// using fxamacker's cbor library ("github.com/fxamacker/cbor/v2") which is why there are cbor tags
// included. The tag field values correspond to the IANA COSE keys that give their respective
// values.
// See §6.4.1.1 https://www.w3.org/TR/webauthn/#sctn-encoded-credPubKey-examples for examples of this
// COSE data.
type PublicKeyData struct {
	// Decode the results to int by default.
	_struct bool `cbor:",keyasint" json:"public_key"`
	// The type of key created. Should be OKP, EC2, or RSA.
	KeyType int `cbor:"1,keyasint" json:"kty"`
	// A COSEAlgorithmIdentifier for the algorithm used to derive the key signature.
	Algorithm int `cbor:"3,keyasint" json:"alg"`
}

func (key *PublicKeyData) GetAlgorithm() int {
	return key.Algorithm
}

// Figure out what kind of COSE material was provided and create the data for the new key
func ParsePublicKey(keyBytes []byte) (PublicKey, error) {
	pk := PublicKeyData{}
	cbor.Unmarshal(keyBytes, &pk)
	switch COSEKeyType(pk.KeyType) {
	case OctetKey:
		var o OKPPublicKeyData
		cbor.Unmarshal(keyBytes, &o)
		o.PublicKeyData = pk
		return &o, nil
	case EllipticKey:
		var e EC2PublicKeyData
		cbor.Unmarshal(keyBytes, &e)
		e.PublicKeyData = pk
		return &e, nil
	case RSAKey:
		var r RSAPublicKeyData
		cbor.Unmarshal(keyBytes, &r)
		r.PublicKeyData = pk
		return &r, nil
	default:
		return nil, errors.New("unsupported key")
	}
}
