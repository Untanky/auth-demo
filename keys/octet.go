package keys

import "crypto/ed25519"

type OKPPublicKeyData struct {
	PublicKeyData
	Curve int64
	// A byte string that holds the x coordinate of the key.
	XCoord []byte `cbor:"-2,keyasint,omitempty" json:"x"`
}

// Verify Octet PublicKey Pair (OKP) Public PublicKey Signature
func (k *OKPPublicKeyData) Verify(data []byte, sig []byte) (bool, error) {
	var key ed25519.PublicKey = make([]byte, ed25519.PublicKeySize)
	copy(key, k.XCoord)
	return ed25519.Verify(key, data, sig), nil
}

// The PublicKey Type derived from the IANA COSE AuthData
type COSEKeyType int

const (
	// OctetKey is an Octet PublicKey
	OctetKey COSEKeyType = 1
	// EllipticKey is an Elliptic Curve Public PublicKey
	EllipticKey COSEKeyType = 2
	// RSAKey is an RSA Public PublicKey
	RSAKey COSEKeyType = 3
)
