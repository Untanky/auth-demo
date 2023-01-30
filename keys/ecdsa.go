package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"math/big"
)

type EC2PublicKeyData struct {
	PublicKeyData
	// If the key type is EC2, the curve on which we derive the signature from.
	Curve int64 `cbor:"-1,keyasint,omitempty" json:"crv"`
	// A byte string 32 bytes in length that holds the x coordinate of the key.
	XCoord []byte `cbor:"-2,keyasint,omitempty" json:"x"`
	// A byte string 32 bytes in length that holds the y coordinate of the key.
	YCoord []byte `cbor:"-3,keyasint,omitempty" json:"y"`
}

// Verify Elliptic Curce Public PublicKey Signature
func (k *EC2PublicKeyData) Verify(data []byte, sig []byte) (bool, error) {
	var curve elliptic.Curve
	switch COSEAlgorithmIdentifier(k.Algorithm) {
	case AlgES512: // IANA COSE code for ECDSA w/ SHA-512
		curve = elliptic.P521()
	case AlgES384: // IANA COSE code for ECDSA w/ SHA-384
		curve = elliptic.P384()
	case AlgES256: // IANA COSE code for ECDSA w/ SHA-256
		curve = elliptic.P256()
	default:
		return false, errors.New("unsupported algorithm")
	}

	pubkey := &ecdsa.PublicKey{
		Curve: curve,
		X:     big.NewInt(0).SetBytes(k.XCoord),
		Y:     big.NewInt(0).SetBytes(k.YCoord),
	}

	type ECDSASignature struct {
		R, S *big.Int
	}

	e := &ECDSASignature{}
	f := HasherFromCOSEAlg(COSEAlgorithmIdentifier(k.PublicKeyData.Algorithm))
	h := f()
	h.Write(data)
	_, err := asn1.Unmarshal(sig, e)
	if err != nil {
		return false, errors.New("Signature not provided or nul")
	}
	return ecdsa.Verify(pubkey, h.Sum(nil), e.R, e.S), nil
}
