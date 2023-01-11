package keys

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"math/big"
)

type RSAPublicKeyData struct {
	PublicKeyData
	// Represents the modulus parameter for the RSA algorithm
	Modulus []byte `cbor:"-1,keyasint,omitempty" json:"n"`
	// Represents the exponent parameter for the RSA algorithm
	Exponent []byte `cbor:"-2,keyasint,omitempty" json:"e"`
}

// Verify RSA Public PublicKey Signature
func (k *RSAPublicKeyData) Verify(data []byte, sig []byte) (bool, error) {
	pubkey := &rsa.PublicKey{
		N: big.NewInt(0).SetBytes(k.Modulus),
		E: int(uint(k.Exponent[2]) | uint(k.Exponent[1])<<8 | uint(k.Exponent[0])<<16),
	}

	f := HasherFromCOSEAlg(COSEAlgorithmIdentifier(k.PublicKeyData.Algorithm))
	h := f()
	h.Write(data)

	var hash crypto.Hash
	switch COSEAlgorithmIdentifier(k.PublicKeyData.Algorithm) {
	case AlgRS1:
		hash = crypto.SHA1
	case AlgPS256, AlgRS256:
		hash = crypto.SHA256
	case AlgPS384, AlgRS384:
		hash = crypto.SHA384
	case AlgPS512, AlgRS512:
		hash = crypto.SHA512
	default:
		return false, errors.New("unsupported algorithm")
	}
	switch COSEAlgorithmIdentifier(k.PublicKeyData.Algorithm) {
	case AlgPS256, AlgPS384, AlgPS512:
		err := rsa.VerifyPSS(pubkey, hash, h.Sum(nil), sig, nil)
		return err == nil, err

	case AlgRS1, AlgRS256, AlgRS384, AlgRS512:
		err := rsa.VerifyPKCS1v15(pubkey, hash, h.Sum(nil), sig)
		return err == nil, err
	default:
		return false, errors.New("unsupported algorithm")
	}
}
