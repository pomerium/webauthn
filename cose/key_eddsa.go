package cose

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// An EdDSAPublicKey is a public key using EdDSA.
type EdDSAPublicKey struct {
	key ed25519.PublicKey
}

// UnmarshalEdDSAPublicKey unmarshals an EdDSA key using the COSE_Key format.
func UnmarshalEdDSAPublicKey(raw []byte) (key *EdDSAPublicKey, remaining []byte, err error) {
	var obj publicKeyStructureOKP
	decoder := cbor.NewDecoder(bytes.NewReader(raw))
	err = decoder.Decode(&obj)
	if err != nil {
		return nil, nil, err
	}

	// algorithm is optional, so default to EdDSA
	if obj.Algorithm == 0 {
		obj.Algorithm = AlgorithmEdDSA
	}

	if obj.Type != KeyTypeOctet {
		return nil, nil, fmt.Errorf("%w: invalid key type", ErrInvalidPublicKey)
	}

	switch obj.Algorithm {
	case AlgorithmEdDSA:
	default:
		return nil, nil, fmt.Errorf("%w: invalid algorithm", ErrUnsupportedAlgorithm)
	}

	switch obj.Curve {
	case CurveEd25519:
	default:
		return nil, nil, ErrUnsupportedCurve
	}

	if len(obj.XCoordinate) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("%w: invalid x-coordinate size", ErrInvalidPublicKey)
	}

	key = &EdDSAPublicKey{
		key: obj.XCoordinate,
	}
	remaining = raw[decoder.NumBytesRead():]
	return key, remaining, nil
}

// Algorithm returns EdDSA.
func (EdDSAPublicKey) Algorithm() Algorithm {
	return AlgorithmEdDSA
}

// CryptoPublicKey returns the crypto EdDSA public key.
func (key EdDSAPublicKey) CryptoPublicKey() crypto.PublicKey {
	return key.key
}

// Type returns OKP.
func (EdDSAPublicKey) Type() KeyType {
	return KeyTypeOctet
}

// Marshal marshals the key.
func (key EdDSAPublicKey) Marshal() ([]byte, error) {
	obj := publicKeyStructureOKP{
		Type:        key.Type(),
		Algorithm:   key.Algorithm(),
		Curve:       CurveEd25519,
		XCoordinate: key.key,
	}
	return cbor.Marshal(obj)
}

// Verify returns true if the signature is a valid EdDSA signature for data.
func (key EdDSAPublicKey) Verify(data, signature []byte) error {
	if !ed25519.Verify(key.key, data, signature) {
		return ErrInvalidSignature
	}

	return nil
}
