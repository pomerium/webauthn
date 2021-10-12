package webauthn

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicKeyAssertionCredential_MarshalJSON(t *testing.T) {
	rawJSON, err := os.ReadFile("testdata/assertionNoneResponse.json")
	require.NoError(t, err)

	var actual PublicKeyAssertionCredential
	err = json.Unmarshal(rawJSON, &actual)
	assert.NoError(t, err)

	actualJSON, err := actual.MarshalJSON()
	assert.NoError(t, err)
	assert.JSONEq(t, string(rawJSON), string(actualJSON))
}

func TestPublicKeyCreationCredential_MarshalJSON(t *testing.T) {
	rawJSON, err := os.ReadFile("testdata/attestationNoneResponse.json")
	require.NoError(t, err)

	var actual PublicKeyCreationCredential
	err = json.Unmarshal(rawJSON, &actual)
	assert.NoError(t, err)

	actualJSON, err := actual.MarshalJSON()
	assert.NoError(t, err)
	assert.JSONEq(t, string(rawJSON), string(actualJSON))
}

func TestPublicKeyCredentialCreationOptions_MarshalJSON(t *testing.T) {
	rawJSON, err := os.ReadFile("testdata/attestationTPMSHA1Options.json")
	require.NoError(t, err)

	var actual PublicKeyCredentialCreationOptions
	err = json.Unmarshal(rawJSON, &actual)
	assert.NoError(t, err)

	actualJSON, err := actual.MarshalJSON()
	assert.NoError(t, err)
	assert.JSONEq(t, string(rawJSON), string(actualJSON))
}
