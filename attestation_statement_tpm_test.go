package webauthn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyTPMAttestationStatement(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, name := range []string{"TPMSHA1", "TPMSHA256"} {
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
						Type:      AttestationTypeAttestationCA,
						TrustPath: certificates,
					}, result)
				}
			})
		}
	})
}
