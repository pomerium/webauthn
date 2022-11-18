package webauthn

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/url"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

func bytesAreEqual(x, y []byte) bool {
	return subtle.ConstantTimeCompare(x, y) == 1
}

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

func originMatches(clientOrigin, relyingPartyOrigin string) bool {
	clientOriginURL, err := url.Parse(clientOrigin)
	if err != nil {
		return false
	}

	relyingPartyOriginURL, err := url.Parse(relyingPartyOrigin)
	if err != nil {
		return false
	}

	clientHost := clientOriginURL.Hostname()
	relyingPartyHost := relyingPartyOriginURL.Hostname()

	for clientHost != "" {
		if clientHost == relyingPartyHost {
			return true
		}

		if idx := strings.Index(clientHost, "."); idx >= 0 {
			clientHost = clientHost[idx+1:]
		} else {
			return false
		}
	}
	return false
}

func stringsAreEqual(x, y string) bool {
	return bytesAreEqual([]byte(x), []byte(y))
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

func fromBase64URL(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, nil
	}
	return base64.RawURLEncoding.DecodeString(encoded)
}

func toBase64URL(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

func fromNullableBase64URL(encoded *string) ([]byte, error) {
	if encoded == nil || *encoded == "" {
		return nil, nil
	}
	return base64.RawURLEncoding.DecodeString(*encoded)
}

func toNullableBase64URL(raw []byte) *string {
	if len(raw) == 0 {
		return nil
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	return &encoded
}
