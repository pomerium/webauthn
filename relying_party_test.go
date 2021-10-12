package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRelyingParty_VerifyAuthenticationCeremony(t *testing.T) {
	t.Skip()
	options := readPublicKeyCredentialRequestOptions(t, "None")
	credential := readPublicKeyAssertionCredential(t, "None")

	cd, _ := credential.Response.UnmarshalClientData()

	t.Logf("%#v", cd.Origin)

	storage := NewInMemoryCredentialStorage()
	storage.SetCredential(&Credential{
		ID: []byte{
			0xf1, 0x3c, 0x7f, 0x08, 0x3c, 0xa2, 0x29, 0xe0,
			0xb4, 0x03, 0xe8, 0x87, 0x34, 0x6e, 0xfc, 0x7f,
			0x98, 0x53, 0x10, 0x3a, 0x30, 0x91, 0x75, 0x67,
			0x39, 0x7a, 0xd1, 0xd8, 0xaf, 0x87, 0x04, 0x61,
			0x87, 0xef, 0x95, 0x31, 0x85, 0x60, 0xf3, 0x5a,
			0x1a, 0x2a, 0xcf, 0x7d, 0xb0, 0x1d, 0x06, 0xb9,
			0x69, 0xf9, 0xab, 0xf4, 0xec, 0xf3, 0x07, 0x3e,
			0xcf, 0x0f, 0x71, 0xe8, 0x84, 0xe8, 0x41, 0x20,
		},
		PublicKey: []byte{},
	})

	rp := NewRelyingParty("https://localhost:44329", storage)
	_, err := rp.VerifyAuthenticationCeremony(options, credential)
	assert.NoError(t, err)
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
	var obj struct {
		ID       string `json:"id"`
		Response struct {
			AuthenticatorData string `json:"authenticatorData"`
			ClientDataJSON    string `json:"clientDataJson"`
			Signature         string `json:"signature"`
			UserHandle        []byte `json:"userHandle"`
		} `json:"response"`
	}
	err = json.Unmarshal(raw, &obj)
	require.NoError(t, err)
	rawID, err := base64.RawURLEncoding.DecodeString(obj.ID)
	require.NoError(t, err)
	rawAuthenticatorData, err := base64.RawURLEncoding.DecodeString(obj.Response.AuthenticatorData)
	require.NoError(t, err)
	rawClientDataJSON, err := base64.RawURLEncoding.DecodeString(obj.Response.ClientDataJSON)
	require.NoError(t, err)
	rawSignature, err := base64.RawURLEncoding.DecodeString(obj.Response.Signature)
	require.NoError(t, err)
	return &PublicKeyAssertionCredential{
		ID:    obj.ID,
		Type:  "public-key",
		RawID: rawID,
		Response: AuthenticatorAssertionResponse{
			ClientDataJSON:    rawClientDataJSON,
			AuthenticatorData: rawAuthenticatorData,
			Signature:         rawSignature,
			UserHandle:        nil,
		},
		ClientExtensionResults: nil,
	}
}
