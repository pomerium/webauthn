package cose

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

type ecdsaVerifyFunc = func(pub *ecdsa.PublicKey, data, signature []byte) error

func getECDSAVerifyFunc(hash crypto.Hash) ecdsaVerifyFunc {
	return func(pub *ecdsa.PublicKey, data, signature []byte) error {
		h := hash.New()
		h.Write(data)
		hashed := h.Sum(nil)

		if !ecdsa.VerifyASN1(pub, hashed, signature) {
			return ErrInvalidSignature
		}
		return nil
	}
}

// An ECDSAPublicKey is a public key using ECDSA.
type ECDSAPublicKey struct {
	algorithm Algorithm
	key       ecdsa.PublicKey
	verify    ecdsaVerifyFunc
}

// UnmarshalECDSAPublicKey unmarshals an ECDSA key using the COSE_Key format.
func UnmarshalECDSAPublicKey(raw []byte) (key *ECDSAPublicKey, remaining []byte, err error) {
	var obj publicKeyStructureEC2
	decoder := cbor.NewDecoder(bytes.NewReader(raw))
	err = decoder.Decode(&obj)
	if err != nil {
		return nil, nil, ErrInvalidPublicKey
	}

	switch obj.Type {
	case KeyTypeElliptic:
	default:
		return nil, nil, fmt.Errorf("%w: %v", ErrUnsupportedKeyType, obj.Type)
	}

	var verify ecdsaVerifyFunc
	switch obj.Algorithm {
	case AlgorithmES256:
		verify = getECDSAVerifyFunc(crypto.SHA256)
	case AlgorithmES384:
		verify = getECDSAVerifyFunc(crypto.SHA384)
	case AlgorithmES512:
		verify = getECDSAVerifyFunc(crypto.SHA512)
	default:
		return nil, nil, fmt.Errorf("%w: %v", ErrUnsupportedAlgorithm, obj.Algorithm)
	}

	var curve elliptic.Curve
	switch obj.Curve {
	case CurveP256:
		curve = elliptic.P256()
	case CurveP384:
		curve = elliptic.P384()
	case CurveP521:
		curve = elliptic.P521()
	default:
		return nil, nil, fmt.Errorf("%w: %v", ErrUnsupportedCurve, obj.Curve)
	}

	key = &ECDSAPublicKey{
		algorithm: obj.Algorithm,
		key: ecdsa.PublicKey{
			Curve: curve,
			X:     big.NewInt(0).SetBytes(obj.XCoordinate),
			Y:     big.NewInt(0).SetBytes(obj.YCoordinate),
		},
		verify: verify,
	}
	remaining = raw[decoder.NumBytesRead():]
	return key, remaining, nil
}

// Algorithm returns the ECDSA algorithm.
func (key ECDSAPublicKey) Algorithm() Algorithm {
	return key.algorithm
}

// CryptoPublicKey returns the crypto ECDSA public key.
func (key ECDSAPublicKey) CryptoPublicKey() crypto.PublicKey {
	return key.key
}

// Type returns EC2.
func (ECDSAPublicKey) Type() KeyType {
	return KeyTypeElliptic
}

// Verify returns true if the signature is a valid ECDSA signature for data.
func (key ECDSAPublicKey) Verify(data, signature []byte) error {
	return key.verify(&key.key, data, signature)
}
