package webauthn

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRelyingParty_VerifyAuthenticationCeremony(t *testing.T) {
	options := readPublicKeyCredentialRequestOptions(t, "GoogleTitan")
	credential := readPublicKeyAssertionCredential(t, "GoogleTitan")

	storage := NewInMemoryCredentialStorage()
	// authentication assumes an existing public key, so set it
	_ = storage.SetCredential(context.Background(), &Credential{
		ID: []byte{
			0xed, 0xc5, 0x97, 0xe5, 0x51, 0xb5, 0x1f, 0xb2,
			0x60, 0x04, 0x05, 0x6d, 0xc5, 0xfd, 0xef, 0x69,
			0x4d, 0xd1, 0xc6, 0xfc, 0xa4, 0xb5, 0x2c, 0x84,
			0xa4, 0xbc, 0x5c, 0x0a, 0xae, 0x8b, 0x6a, 0xa5,
			0x98, 0xdd, 0x65, 0x75, 0x61, 0x67, 0x0a, 0xbd,
			0xa8, 0xc3, 0xec, 0xa1, 0xda, 0x1d, 0xd1, 0x28,
			0xa4, 0xd4, 0x22, 0x6d, 0xb0, 0x9b, 0xbd, 0x3a,
			0x41, 0xaa, 0xd1, 0xd7, 0x49, 0x94, 0x67, 0xaa,
		},
		PublicKey: []byte{
			0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21,
			0x58, 0x20, 0x93, 0x9f, 0x98, 0xa3, 0xdd, 0x89,
			0x22, 0xfb, 0xa0, 0xa8, 0x2c, 0xbd, 0xf7, 0xf7,
			0xa3, 0x8b, 0x57, 0xd9, 0x58, 0xf8, 0xc3, 0xa4,
			0xed, 0xc6, 0x64, 0xf7, 0x46, 0x3b, 0xcf, 0xe3,
			0x45, 0x64, 0x22, 0x58, 0x20, 0x31, 0xa3, 0xaf,
			0xa1, 0xda, 0x87, 0x5a, 0x08, 0x4b, 0xd0, 0x3a,
			0xcf, 0x33, 0x3e, 0xf8, 0x40, 0x81, 0x1a, 0x2f,
			0xe4, 0xa1, 0x0b, 0x4a, 0x4b, 0x51, 0xa9, 0xc0,
			0xcb, 0xaf, 0x4b, 0x84, 0xfb,
		},
	})
	rp := NewRelyingParty("http://localhost:5000", storage)
	_, err := rp.VerifyAuthenticationCeremony(context.Background(), options, credential)
	assert.NoError(t, err)
}

func TestRelyingParty_VerifyRegistrationCeremony(t *testing.T) {
	options := readPublicKeyCredentialCreationOptions(t, "GoogleTitan")
	credential := readPublicKeyCreationCredential(t, "GoogleTitan")

	storage := NewInMemoryCredentialStorage()
	rp := NewRelyingParty("http://localhost:5000", storage)
	_, err := rp.VerifyRegistrationCeremony(context.Background(), options, credential)
	assert.NoError(t, err)
}

func readPublicKeyCredentialCreationOptions(t *testing.T, name string) *PublicKeyCredentialCreationOptions {
	raw, err := os.ReadFile("testdata/attestation" + name + "Options.json")
	require.NoError(t, err)
	var options PublicKeyCredentialCreationOptions
	err = json.Unmarshal(raw, &options)
	require.NoError(t, err)
	return &options
}

func readPublicKeyCreationCredential(t *testing.T, name string) *PublicKeyCreationCredential {
	raw, err := os.ReadFile("testdata/attestation" + name + "Response.json")
	require.NoError(t, err)
	var credential PublicKeyCreationCredential
	err = json.Unmarshal(raw, &credential)
	require.NoError(t, err)
	return &credential
}

func readPublicKeyCredentialRequestOptions(t *testing.T, name string) *PublicKeyCredentialRequestOptions {
	raw, err := os.ReadFile("testdata/assertion" + name + "Options.json")
	require.NoError(t, err)
	var options PublicKeyCredentialRequestOptions
	err = json.Unmarshal(raw, &options)
	require.NoError(t, err)
	return &options
}

func readPublicKeyAssertionCredential(t *testing.T, name string) *PublicKeyAssertionCredential {
	raw, err := os.ReadFile("testdata/assertion" + name + "Response.json")
	require.NoError(t, err)
	var credential PublicKeyAssertionCredential
	err = json.Unmarshal(raw, &credential)
	require.NoError(t, err)
	return &credential
}
