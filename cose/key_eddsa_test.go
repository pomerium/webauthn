package cose

import (
	"crypto/ed25519"
	"math/rand"
	"testing"

	"github.com/Universal-Health-Chain/uhc-cloudflare-circl/sign/ed448"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalEdDSAPublicKey(t *testing.T) {
	random := rand.New(rand.NewSource(1))

	t.Run("valid", func(t *testing.T) {
		pub, _, err := ed25519.GenerateKey(random)
		require.NoError(t, err)
		rawKey, err := cbor.Marshal(map[int]interface{}{
			1:  KeyTypeOctet,
			3:  AlgorithmEdDSA,
			-1: CurveEd25519,
			-2: pub,
		})
		require.NoError(t, err)

		key, remaining, err := UnmarshalPublicKey(rawKey)
		assert.NoError(t, err)
		assert.Empty(t, remaining)

		assert.Equal(t, pub, key.CryptoPublicKey())
	})
	t.Run("unsupported curve", func(t *testing.T) {
		pub, _, err := ed448.GenerateKey(random)
		require.NoError(t, err)
		rawKey, err := cbor.Marshal(map[int]interface{}{
			1:  KeyTypeOctet,
			3:  AlgorithmEdDSA,
			-1: CurveEd448,
			-2: pub,
		})
		require.NoError(t, err)

		_, _, err = UnmarshalPublicKey(rawKey)
		assert.ErrorIs(t, err, ErrUnsupportedCurve)
	})
	t.Run("unsupported algorithm", func(t *testing.T) {
		pub, _, err := ed25519.GenerateKey(random)
		require.NoError(t, err)
		rawKey, err := cbor.Marshal(map[int]interface{}{
			1:  KeyTypeOctet,
			3:  -34,
			-1: CurveEd25519,
			-2: pub,
		})
		require.NoError(t, err)

		_, _, err = UnmarshalPublicKey(rawKey)
		assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
	})
}

func TestEdDSAPublicKey_Verify(t *testing.T) {
	random := rand.New(rand.NewSource(1))
	pub, priv, err := ed25519.GenerateKey(random)
	require.NoError(t, err)
	rawKey, err := cbor.Marshal(map[int]interface{}{
		1:  KeyTypeOctet,
		3:  AlgorithmEdDSA,
		-1: CurveEd25519,
		-2: pub,
	})
	require.NoError(t, err)

	payload := []byte("Hello World")

	key, remaining, err := UnmarshalPublicKey(rawKey)
	assert.NoError(t, err)
	assert.Empty(t, remaining)

	t.Run("valid", func(t *testing.T) {
		signature := ed25519.Sign(priv, payload)

		err = key.Verify(payload, signature)
		assert.NoError(t, err)
	})

	t.Run("invalid", func(t *testing.T) {
		_, other, err := ed25519.GenerateKey(random)
		require.NoError(t, err)

		signature := ed25519.Sign(other, payload)

		err = key.Verify(payload, signature)
		assert.ErrorIs(t, err, ErrInvalidSignature)
	})
}
