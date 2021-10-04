package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"math/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalECDSAPublicKey(t *testing.T) {
	random := rand.New(rand.NewSource(1))

	type TestCase struct {
		Name      string
		PublicKey crypto.PublicKey
		Algorithm Algorithm
		RawKey    []byte
		Error     error
	}

	var testCases []TestCase

	for _, alg := range []Algorithm{
		AlgorithmES256,
		AlgorithmES384,
		AlgorithmES512,
	} {
		for _, curve := range []Curve{
			CurveP256,
			CurveP384,
			CurveP521,
		} {
			ellipticCurve, ok := curve.EllipticCurve()
			require.True(t, ok)

			genKey, err := ecdsa.GenerateKey(ellipticCurve, random)
			require.NoError(t, err)
			rawKey, err := cbor.Marshal(map[int]interface{}{
				1:  KeyTypeElliptic,
				3:  alg,
				-1: curve,
				-2: genKey.X.Bytes(),
				-3: genKey.Y.Bytes(),
			})
			require.NoError(t, err)
			testCases = append(testCases, TestCase{
				Name:      alg.String() + " " + curve.String(),
				PublicKey: genKey.Public().(*ecdsa.PublicKey),
				RawKey:    rawKey,
				Algorithm: alg,
			})
		}
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			key, remaining, err := UnmarshalPublicKey(testCase.RawKey)
			assert.NoError(t, err)
			assert.Empty(t, remaining)

			assert.Equal(t, testCase.Algorithm, key.Algorithm())
			assert.Equal(t, KeyTypeElliptic, key.Type())
			assert.Equal(t, testCase.PublicKey, key.CryptoPublicKey())
		})
	}
}

func TestECDSAPublicKey_Verify(t *testing.T) {
	random := rand.New(rand.NewSource(1))
	ellipticCurve, ok := CurveP256.EllipticCurve()
	require.True(t, ok)
	genKey, err := ecdsa.GenerateKey(ellipticCurve, random)
	require.NoError(t, err)
	rawKey, err := cbor.Marshal(map[int]interface{}{
		1:  KeyTypeElliptic,
		3:  AlgorithmES256,
		-1: CurveP256,
		-2: genKey.X.Bytes(),
		-3: genKey.Y.Bytes(),
	})
	require.NoError(t, err)

	payload := []byte("Hello World")

	key, remaining, err := UnmarshalPublicKey(rawKey)
	assert.NoError(t, err)
	assert.Empty(t, remaining)

	t.Run("valid", func(t *testing.T) {
		digest := sha256.Sum256(payload)
		signature, err := genKey.Sign(random, digest[:], nil)
		require.NoError(t, err)

		err = key.Verify(payload, signature)
		assert.NoError(t, err)
	})

	t.Run("invalid", func(t *testing.T) {
		digest := sha512.Sum384(payload)
		signature, err := genKey.Sign(random, digest[:], nil)
		require.NoError(t, err)

		err = key.Verify(payload, signature)
		assert.ErrorIs(t, err, ErrInvalidSignature)
	})
}
