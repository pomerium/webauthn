package tpm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVendorID(t *testing.T) {
	microsoft := RegisteredVendors[VendorID{0x4D, 0x53, 0x46, 0x54}]
	assert.Equal(t, "Microsoft", microsoft.Name)
	assert.Equal(t, "MSFT", microsoft.ID.String())

	t.Run("valid", func(t *testing.T) {
		vendorID, err := UnmarshalVendorID("id:4D534654")
		assert.NoError(t, err)
		assert.Equal(t, microsoft.ID, vendorID)
	})
	t.Run("wrong length", func(t *testing.T) {
		_, err := UnmarshalVendorID("4D534654")
		assert.Error(t, err)
	})
	t.Run("missing id", func(t *testing.T) {
		_, err := UnmarshalVendorID("0004D534654")
		assert.Error(t, err)
	})
	t.Run("not hex", func(t *testing.T) {
		_, err := UnmarshalVendorID("id:ZZZZZZZZ")
		assert.Error(t, err)
	})
}
