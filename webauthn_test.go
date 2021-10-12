package webauthn

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBase64RawURLBytes(t *testing.T) {
	rawJSON := []byte(`"-8OfJQc6LzKXCIdLZeD27v-ZLUhjTANxzqMjUNMlCmTKGYYK54hQ56AqAjlHotHll688d0ZRM6_L8lGOq3CZNw"`)

	expect := Base64RawURLBytes{
		0xfb, 0xc3, 0x9f, 0x25, 0x07, 0x3a, 0x2f, 0x32,
		0x97, 0x08, 0x87, 0x4b, 0x65, 0xe0, 0xf6, 0xee,
		0xff, 0x99, 0x2d, 0x48, 0x63, 0x4c, 0x03, 0x71,
		0xce, 0xa3, 0x23, 0x50, 0xd3, 0x25, 0x0a, 0x64,
		0xca, 0x19, 0x86, 0x0a, 0xe7, 0x88, 0x50, 0xe7,
		0xa0, 0x2a, 0x02, 0x39, 0x47, 0xa2, 0xd1, 0xe5,
		0x97, 0xaf, 0x3c, 0x77, 0x46, 0x51, 0x33, 0xaf,
		0xcb, 0xf2, 0x51, 0x8e, 0xab, 0x70, 0x99, 0x37,
	}
	var actual Base64RawURLBytes
	err := json.Unmarshal(rawJSON, &actual)
	assert.NoError(t, err)
	assert.Equal(t, expect, actual)

	encoded, err := actual.MarshalJSON()
	assert.NoError(t, err)
	assert.Equal(t, rawJSON, encoded)
}
