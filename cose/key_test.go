package cose

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalPublicKey(t *testing.T) {
	t.Run("invalid cbor", func(t *testing.T) {
		raw, err := cbor.Marshal([]int{1, 2, 3})
		require.NoError(t, err)

		_, _, err = UnmarshalPublicKey(raw)
		assert.ErrorIs(t, err, ErrInvalidPublicKey)
	})
	t.Run("invalid key type", func(t *testing.T) {
		raw, err := cbor.Marshal(map[int]interface{}{
			1: 0,
		})
		require.NoError(t, err)

		_, _, err = UnmarshalPublicKey(raw)
		assert.ErrorIs(t, err, ErrUnsupportedKeyType)
	})
}
