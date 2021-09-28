package cose

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

type rsaVerifyFunc func(pub *rsa.PublicKey, data, signature []byte) error

func getRSAVerifyPKCS1v15Func(hash crypto.Hash) rsaVerifyFunc {
	return func(pub *rsa.PublicKey, data, signature []byte) error {
		h := hash.New()
		h.Write(data)
		hashed := h.Sum(nil)

		return rsa.VerifyPKCS1v15(pub, hash, hashed, signature)
	}
}

func getRSAVerifyPSSFunc(hash crypto.Hash) rsaVerifyFunc {
	return func(pub *rsa.PublicKey, data, signature []byte) error {
		h := hash.New()
		h.Write(data)
		hashed := h.Sum(nil)

		return rsa.VerifyPSS(pub, hash, hashed, signature, nil)
	}
}

// An RSAPublicKey is a public key using RSA.
type RSAPublicKey struct {
	algorithm Algorithm
	key       rsa.PublicKey
	verify    rsaVerifyFunc
}

// UnmarshalRSAPublicKey unmarshals an RSA key using the COSE_Key format.
func UnmarshalRSAPublicKey(raw []byte) (key *RSAPublicKey, remaining []byte, err error) {
	var obj publicKeyStructureRSA
	decoder := cbor.NewDecoder(bytes.NewReader(raw))
	err = decoder.Decode(&obj)
	if err != nil {
		return nil, nil, ErrInvalidPublicKey
	}

	switch obj.Type {
	case KeyTypeRSA:
	default:
		return nil, nil, fmt.Errorf("%w: %v", ErrUnsupportedKeyType, obj.Type)
	}

	var verify rsaVerifyFunc
	switch obj.Algorithm {
	case AlgorithmRS1:
		verify = getRSAVerifyPKCS1v15Func(crypto.SHA1)
	case AlgorithmRS256:
		verify = getRSAVerifyPKCS1v15Func(crypto.SHA256)
	case AlgorithmRS384:
		verify = getRSAVerifyPKCS1v15Func(crypto.SHA384)
	case AlgorithmRS512:
		verify = getRSAVerifyPKCS1v15Func(crypto.SHA512)
	case AlgorithmPS256:
		verify = getRSAVerifyPSSFunc(crypto.SHA256)
	case AlgorithmPS384:
		verify = getRSAVerifyPSSFunc(crypto.SHA384)
	case AlgorithmPS512:
		verify = getRSAVerifyPSSFunc(crypto.SHA512)
	default:
		return nil, nil, fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, obj.Algorithm)
	}

	key = &RSAPublicKey{
		algorithm: obj.Algorithm,
		key: rsa.PublicKey{
			// All numbers are stored as unsigned, big-endian integers. This is the same format
			// as big.Int.
			N: big.NewInt(0).SetBytes(obj.Modulus),
			E: int(big.NewInt(0).SetBytes(obj.Exponent).Int64()),
		},
		verify: verify,
	}
	remaining = raw[decoder.NumBytesRead():]
	err = nil
	return key, remaining, err
}

// Algorithm returns the RSA algorithm.
func (key RSAPublicKey) Algorithm() Algorithm {
	return key.algorithm
}

// CryptoPublicKey returns the crypto RSA public key.
func (key RSAPublicKey) CryptoPublicKey() crypto.PublicKey {
	return key.key
}

// Type returns RSA.
func (RSAPublicKey) Type() KeyType {
	return KeyTypeRSA
}

// Verify returns true if the signature is a valid RSA signature for data.
func (key RSAPublicKey) Verify(data, signature []byte) error {
	return key.verify(&key.key, data, signature)
}
