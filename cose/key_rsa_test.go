package cose

import (
	"crypto"
	"crypto/rsa"
	"math/big"
	"math/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalRSAPublicKey(t *testing.T) {
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
		AlgorithmRS1,
		AlgorithmRS256,
		AlgorithmRS384,
		AlgorithmRS512,
		AlgorithmPS256,
		AlgorithmPS384,
		AlgorithmPS512,
	} {
		genKey, err := rsa.GenerateKey(random, 2048)
		require.NoError(t, err)
		rawKey, err := cbor.Marshal(map[int]interface{}{
			1:  KeyTypeRSA,
			3:  alg,
			-1: genKey.N.Bytes(),
			-2: big.NewInt(int64(genKey.E)).Bytes(),
		})
		require.NoError(t, err)
		testCases = append(testCases, TestCase{
			Name:      alg.String(),
			PublicKey: *genKey.Public().(*rsa.PublicKey),
			RawKey:    rawKey,
			Algorithm: alg,
		})
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			key, remaining, err := UnmarshalPublicKey(testCase.RawKey)
			assert.NoError(t, err)
			assert.Empty(t, remaining)

			assert.Equal(t, testCase.Algorithm, key.Algorithm())
			assert.Equal(t, KeyTypeRSA, key.Type())
			assert.Equal(t, testCase.PublicKey, key.CryptoPublicKey())
		})
	}
}
