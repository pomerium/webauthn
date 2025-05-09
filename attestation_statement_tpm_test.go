package webauthn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyTPMAttestationStatement(t *testing.T) {
	// The example TPM attestation responses include a CA certificate with a
	// negative serial number, which Go no longer allows by default.
	t.Setenv("GODEBUG", "x509negativeserial=1")
	t.Run("valid", func(t *testing.T) {
		for _, name := range []string{"TPMSHA1", "TPMSHA256"} {
			response := readTestAuthenticatorAttestationResponse(t, name)
			attestationObject, err := response.UnmarshalAttestationObject()
			require.NoError(t, err)
			clientDataJSONHash := response.GetClientDataJSONHash()
			t.Run(name, func(t *testing.T) {
				_, err := VerifyAttestationStatement(attestationObject, clientDataJSONHash)
				assert.NoError(t, err)
			})
		}
	})
}
