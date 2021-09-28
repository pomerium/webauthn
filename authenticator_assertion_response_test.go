package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticatorAssertionResponse_GetClientDataJSONHash(t *testing.T) {
	response := readTestAuthenticatorAssertionResponse(t, "None")
	assert.Equal(t, ClientDataJSONHash{
		0xc8, 0x64, 0x21, 0x7a, 0xc6, 0x5b, 0x8d, 0x98,
		0x15, 0xf3, 0x5c, 0x39, 0xda, 0x8e, 0x2f, 0x8e,
		0x5d, 0xdd, 0xe1, 0xf4, 0x13, 0x71, 0x04, 0x4e,
		0x3a, 0x66, 0xc6, 0x31, 0x27, 0x4b, 0x9a, 0x76,
	}, response.GetClientDataJSONHash())
}

func TestAuthenticatorAssertionResponse_UnmarshalAuthenticatorData(t *testing.T) {
	response := readTestAuthenticatorAssertionResponse(t, "None")
	authenticatorData, err := response.UnmarshalAuthenticatorData()
	assert.NoError(t, err)
	assert.Equal(t, &AuthenticatorData{
		RPIDHash: RPIDHash{
			0x49, 0x96, 0x0d, 0xe5, 0x88, 0x0e, 0x8c, 0x68,
			0x74, 0x34, 0x17, 0x0f, 0x64, 0x76, 0x60, 0x5b,
			0x8f, 0xe4, 0xae, 0xb9, 0xa2, 0x86, 0x32, 0xc7,
			0x99, 0x5c, 0xf3, 0xba, 0x83, 0x1d, 0x97, 0x63,
		},
		Flags:     authenticatorFlagsUP,
		SignCount: 52,
	}, authenticatorData)
}

func TestAuthenticatorAssertionResponse_UnmarshalClientData(t *testing.T) {
	response := readTestAuthenticatorAssertionResponse(t, "None")
	clientData, err := response.UnmarshalClientData()
	assert.NoError(t, err)
	assert.Equal(t, &CollectedClientData{
		Type:      "webauthn.get",
		Challenge: "bNhBhi9JITEQuYNPlxoHHj0kzNsVSLMVM0JfgScPZiS7nGF51omGSNLY61FBZ84gG5nRx0EL0tC8Thrl0Aazcg",
		Origin:    "https://localhost:44329",
	}, clientData)
}

func readTestAuthenticatorAssertionResponse(t *testing.T, name string) *AuthenticatorAssertionResponse {
	raw, err := os.ReadFile("testdata/assertion" + name + "Response.json")
	require.NoError(t, err)
	var obj struct {
		Response struct {
			AuthenticatorData string `json:"authenticatorData"`
			ClientDataJSON    string `json:"clientDataJson"`
			Signature         string `json:"signature"`
		} `json:"response"`
	}
	err = json.Unmarshal(raw, &obj)
	require.NoError(t, err)
	rawAuthenticatorData, err := base64.RawURLEncoding.DecodeString(obj.Response.AuthenticatorData)
	require.NoError(t, err)
	rawClientDataJSON, err := base64.RawURLEncoding.DecodeString(obj.Response.ClientDataJSON)
	require.NoError(t, err)
	rawSignature, err := base64.RawURLEncoding.DecodeString(obj.Response.Signature)
	require.NoError(t, err)
	return &AuthenticatorAssertionResponse{
		AuthenticatorData: rawAuthenticatorData,
		ClientDataJSON:    rawClientDataJSON,
		Signature:         rawSignature,
	}
}
