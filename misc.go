package webauthn

import (
	"bytes"

	"github.com/fxamacker/cbor/v2"
)

func concat(bss ...[]byte) []byte {
	sz := 0
	for _, bs := range bss {
		sz += len(bs)
	}
	result := make([]byte, 0, sz)
	for _, bs := range bss {
		result = append(result, bs...)
	}
	return result
}

// extractCBOR splits a byte slice into two parts. The first contains CBOR data. The second the remaining bytes.
func extractCBOR(data []byte) (cborData, remaining []byte, err error) {
	var m interface{}
	decoder := cbor.NewDecoder(bytes.NewReader(data))
	err = decoder.Decode(&m)
	if err != nil {
		return nil, nil, err
	}
	return data[:decoder.NumBytesRead()], data[decoder.NumBytesRead():], nil
}
