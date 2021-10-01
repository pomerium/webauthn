package webauthn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyPackedAttestationStatement(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, name := range []string{"Packed", "Packed512"} {
			response := readTestAuthenticatorAttestationResponse(t, name)
			attestationObject, err := response.UnmarshalAttestationObject()
			require.NoError(t, err)
			clientDataJSONHash := response.GetClientDataJSONHash()
			certificates, _ := attestationObject.Statement.UnmarshalCertificates()
			t.Run(name, func(t *testing.T) {
				result, err := VerifyAttestationStatement(attestationObject, clientDataJSONHash)
				assert.NoError(t, err)
				if certificates == nil {
					assert.Equal(t, &VerifyAttestationStatementResult{
						Type: AttestationTypeSelf,
					}, result)
				} else {
					assert.Equal(t, &VerifyAttestationStatementResult{
						Type:      AttestationTypeBasic,
						TrustPath: certificates,
					}, result)
				}
			})
		}
	})

	t.Run("invalid format", func(t *testing.T) {
		response := readTestAuthenticatorAttestationResponse(t, "None")
		attestationObject, err := response.UnmarshalAttestationObject()
		require.NoError(t, err)
		clientDataJSONHash := response.GetClientDataJSONHash()

		result, err := VerifyPackedAttestationStatement(attestationObject, clientDataJSONHash)
		assert.ErrorIs(t, err, ErrInvalidAttestationStatement)
		assert.Nil(t, result)
	})
	t.Run("invalid certificate", func(t *testing.T) {
		response := readTestAuthenticatorAttestationResponse(t, "Packed")
		attestationObject, err := response.UnmarshalAttestationObject()
		require.NoError(t, err)
		clientDataJSONHash := response.GetClientDataJSONHash()
		attestationObject.Statement["x5c"] = []byte("INVALID")

		result, err := VerifyPackedAttestationStatement(attestationObject, clientDataJSONHash)
		assert.ErrorIs(t, err, ErrInvalidAttestationStatement)
		assert.Nil(t, result)
	})
	t.Run("invalid authenticator data", func(t *testing.T) {
		response := readTestAuthenticatorAttestationResponse(t, "Packed")
		attestationObject, err := response.UnmarshalAttestationObject()
		require.NoError(t, err)
		clientDataJSONHash := response.GetClientDataJSONHash()
		attestationObject.AuthData = []byte("INVALID")

		result, err := VerifyPackedAttestationStatement(attestationObject, clientDataJSONHash)
		assert.ErrorIs(t, err, ErrInvalidAttestationStatement)
		assert.Nil(t, result)
	})
	t.Run("invalid signature", func(t *testing.T) {
		response := readTestAuthenticatorAttestationResponse(t, "Packed")
		attestationObject, err := response.UnmarshalAttestationObject()
		require.NoError(t, err)
		clientDataJSONHash := response.GetClientDataJSONHash()
		attestationObject.Statement["sig"] = []byte("INVALID")

		result, err := VerifyPackedAttestationStatement(attestationObject, clientDataJSONHash)
		assert.ErrorIs(t, err, ErrInvalidAttestationStatement)
		assert.Nil(t, result)
	})
}
