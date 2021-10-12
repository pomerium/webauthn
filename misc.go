package webauthn

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"encoding/binary"
	"io"

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

func hashIsEqual(hash crypto.Hash, data []byte, expectedHashSum []byte) bool {
	if !hash.Available() {
		return false
	}
	h := hash.New()
	h.Write(data)
	return subtle.ConstantTimeCompare(h.Sum(nil), expectedHashSum) == 1
}

func write(w io.Writer, bs ...byte) error {
	_, err := w.Write(bs)
	return err
}

func writeUint16(w io.Writer, v uint16) error {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	_, err := w.Write(buf[:])
	return err
}

func writeUint32(w io.Writer, v uint32) error {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	_, err := w.Write(buf[:])
	return err
}
