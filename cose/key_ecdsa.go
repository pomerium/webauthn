package cose

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"

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

// RawX962ECC represents the Raw ANSI X9.62 public key format for ALG_KEY_ECC_X962_RAW as defined in:
// https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#public-key-representation-formats
type RawX962ECC [65]byte

// NewRawX962ECC creates a new RawX962ECC.
func NewRawX962ECC(x, y [32]byte) RawX962ECC {
	var arr RawX962ECC
	arr[0] = 0x04
	copy(arr[1:], x[:])
	copy(arr[1+32:], y[:])
	return arr
}

// An ECDSAPublicKey is a public key using ECDSA.
type ECDSAPublicKey struct {
	algorithm Algorithm
	key       ecdsa.PublicKey
	verify    ecdsaVerifyFunc
}

// NewECDSAPublicKey creates a new ECDSAPublicKey from an existing key.
func NewECDSAPublicKey(
	algorithm Algorithm,
	publicKey ecdsa.PublicKey,
) (*ECDSAPublicKey, error) {
	var verify ecdsaVerifyFunc
	switch algorithm {
	case AlgorithmES256:
		verify = getECDSAVerifyFunc(crypto.SHA256)
	case AlgorithmES384:
		verify = getECDSAVerifyFunc(crypto.SHA384)
	case AlgorithmES512:
		verify = getECDSAVerifyFunc(crypto.SHA512)
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedAlgorithm, algorithm)
	}

	return &ECDSAPublicKey{
		algorithm: algorithm,
		key:       publicKey,
		verify:    verify,
	}, nil
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

	// Coordinates are left-padded to the curve's field size since some
	// encoders strip leading zero bytes.
	size := (curve.Params().BitSize + 7) / 8
	if len(obj.XCoordinate) > size || len(obj.YCoordinate) > size {
		return nil, nil, ErrInvalidPublicKey
	}
	uncompressed := make([]byte, 1+2*size)
	uncompressed[0] = 0x04
	copy(uncompressed[1+size-len(obj.XCoordinate):1+size], obj.XCoordinate)
	copy(uncompressed[1+2*size-len(obj.YCoordinate):], obj.YCoordinate)

	publicKey, err := ecdsa.ParseUncompressedPublicKey(curve, uncompressed)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}

	key, err = NewECDSAPublicKey(obj.Algorithm, *publicKey)
	if err != nil {
		return nil, nil, err
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
	return &key.key
}

// RawX962ECC returns the RawX962ECC formatted public key.
func (key ECDSAPublicKey) RawX962ECC() RawX962ECC {
	var x, y [32]byte
	xCoordinate, yCoordinate, err := key.coordinates()
	if err != nil {
		return RawX962ECC{}
	}
	copy(x[:], xCoordinate)
	copy(y[:], yCoordinate)
	return NewRawX962ECC(x, y)
}

// Type returns EC2.
func (ECDSAPublicKey) Type() KeyType {
	return KeyTypeElliptic
}

// Marshal marshals the key.
func (key ECDSAPublicKey) Marshal() ([]byte, error) {
	var curve Curve
	switch key.key.Curve {
	case elliptic.P256():
		curve = CurveP256
	case elliptic.P384():
		curve = CurveP384
	case elliptic.P521():
		curve = CurveP521
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedCurve, key.key.Curve)
	}

	xCoordinate, yCoordinate, err := key.coordinates()
	if err != nil {
		return nil, err
	}

	obj := publicKeyStructureEC2{
		Type:        key.Type(),
		Algorithm:   key.Algorithm(),
		Curve:       curve,
		XCoordinate: xCoordinate,
		YCoordinate: yCoordinate,
	}
	return cbor.Marshal(obj)
}

// coordinates returns the fixed-size big-endian X and Y coordinates of the key.
func (key ECDSAPublicKey) coordinates() (x, y []byte, err error) {
	uncompressed, err := key.key.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}
	size := (len(uncompressed) - 1) / 2
	return uncompressed[1 : 1+size], uncompressed[1+size:], nil
}

// Verify returns true if the signature is a valid ECDSA signature for data.
func (key ECDSAPublicKey) Verify(data, signature []byte) error {
	return key.verify(&key.key, data, signature)
}
