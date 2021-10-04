package cose

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Errors
var (
	ErrInvalidPublicKey     = errors.New("invalid public key")
	ErrInvalidSignature     = errors.New("invalid signature")
	ErrUnsupportedAlgorithm = errors.New("unsupported COSE algorithm")
	ErrUnsupportedCurve     = errors.New("unsupported elliptic curve")
	ErrUnsupportedKeyType   = errors.New("unsupported COSE key type")
)

// publicKeyStructure is the base type for all supported public key types.
type publicKeyStructure struct {
	Type      KeyType   `cbor:"1,keyasint,omitempty" json:"kty"`
	Algorithm Algorithm `cbor:"3,keyasint,omitempty" json:"alg"`
}

// publicKeyStructureOKP defines the CBOR encoding of an EC2 key as specified in:
// https://datatracker.ietf.org/doc/html/rfc8152#section-13.1.1.
type publicKeyStructureEC2 struct {
	Type        KeyType   `cbor:"1,keyasint,omitempty" json:"kty"`
	Algorithm   Algorithm `cbor:"3,keyasint,omitempty" json:"alg"`
	Curve       Curve     `cbor:"-1,keyasint,omitempty" json:"crv"`
	XCoordinate []byte    `cbor:"-2,keyasint,omitempty" json:"x"`
	YCoordinate []byte    `cbor:"-3,keyasint,omitempty" json:"y"`
}

// publicKeyStructureOKP defines the CBOR encoding of an OKP key as specified in:
// https://datatracker.ietf.org/doc/html/rfc8152#section-13.2.
type publicKeyStructureOKP struct {
	Type        KeyType   `cbor:"1,keyasint,omitempty" json:"kty"`
	Algorithm   Algorithm `cbor:"3,keyasint,omitempty" json:"alg"`
	Curve       Curve     `cbor:"-1,keyasint,omitempty" json:"crv"`
	XCoordinate []byte    `cbor:"-2,keyasint,omitempty" json:"x"`
}

// publicKeyStructureRSA defines the CBOR encoding of an RSA key as specified in:
// https://datatracker.ietf.org/doc/html/rfc8230#section-4
type publicKeyStructureRSA struct {
	Type      KeyType   `cbor:"1,keyasint,omitempty" json:"kty"`
	Algorithm Algorithm `cbor:"3,keyasint,omitempty" json:"alg"`
	Modulus   []byte    `cbor:"-1,keyasint,omitempty" json:"n"`
	Exponent  []byte    `cbor:"-2,keyasint,omitempty" json:"e"`
}

// A PublicKey is a credential public key.
type PublicKey interface {
	Algorithm() Algorithm
	CryptoPublicKey() crypto.PublicKey
	Marshal() ([]byte, error)
	Type() KeyType
	Verify(data, signature []byte) error
}

// UnmarshalPublicKey unmarshals a COSE_Key encoded public key from a slice of bytes.
func UnmarshalPublicKey(raw []byte) (key PublicKey, remaining []byte, err error) {
	var base publicKeyStructure
	err = cbor.Unmarshal(raw, &base)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s", ErrInvalidPublicKey, err)
	}

	switch base.Type {
	case KeyTypeElliptic:
		return UnmarshalECDSAPublicKey(raw)
	case KeyTypeOctet:
		return UnmarshalEdDSAPublicKey(raw)
	case KeyTypeRSA:
		return UnmarshalRSAPublicKey(raw)
	}
	return nil, nil, fmt.Errorf("%w: %d", ErrUnsupportedKeyType, base.Type)
}
