package webauthn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyPackedAttestationStatement(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, name := range []string{"Packed", "Packed512", "Windows"} {
			response := readTestAuthenticatorAttestationResponse(t, name)
			attestationObject, err := response.UnmarshalAttestationObject()
			require.NoError(t, err)
			clientDataJSONHash := response.GetClientDataJSONHash()
			t.Run(name, func(t *testing.T) {
				_, err = VerifyAttestationStatement(attestationObject, clientDataJSONHash)
				assert.NoError(t, err)
			})
		}
	})

	t.Run("invalid format", func(t *testing.T) {
		response := readTestAuthenticatorAttestationResponse(t, "None")
		attestationObject, err := response.UnmarshalAttestationObject()
		require.NoError(t, err)
		clientDataJSONHash := response.GetClientDataJSONHash()

		_, err = VerifyPackedAttestationStatement(attestationObject, clientDataJSONHash)
		assert.ErrorIs(t, err, ErrInvalidAttestationStatement)
	})
	t.Run("invalid certificate", func(t *testing.T) {
		response := readTestAuthenticatorAttestationResponse(t, "Packed")
		attestationObject, err := response.UnmarshalAttestationObject()
		require.NoError(t, err)
		clientDataJSONHash := response.GetClientDataJSONHash()
		attestationObject.Statement["x5c"] = []byte("INVALID")

		_, err = VerifyPackedAttestationStatement(attestationObject, clientDataJSONHash)
		assert.ErrorIs(t, err, ErrInvalidAttestationStatement)
	})
	t.Run("invalid authenticator data", func(t *testing.T) {
		response := readTestAuthenticatorAttestationResponse(t, "Packed")
		attestationObject, err := response.UnmarshalAttestationObject()
		require.NoError(t, err)
		clientDataJSONHash := response.GetClientDataJSONHash()
		attestationObject.AuthData = []byte("INVALID")

		_, err = VerifyPackedAttestationStatement(attestationObject, clientDataJSONHash)
		assert.ErrorIs(t, err, ErrInvalidAttestationStatement)
	})
	t.Run("invalid signature", func(t *testing.T) {
		response := readTestAuthenticatorAttestationResponse(t, "Packed")
		attestationObject, err := response.UnmarshalAttestationObject()
		require.NoError(t, err)
		clientDataJSONHash := response.GetClientDataJSONHash()
		attestationObject.Statement["sig"] = []byte("INVALID")

		_, err = VerifyPackedAttestationStatement(attestationObject, clientDataJSONHash)
		assert.ErrorIs(t, err, ErrInvalidAttestationStatement)
	})
}
