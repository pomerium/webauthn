package webauthn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyNoneAttestationStatement(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, name := range []string{"None"} {
			response := readTestAuthenticatorAttestationResponse(t, name)
			attestationObject, err := response.UnmarshalAttestationObject()
			require.NoError(t, err)
			clientDataJSONHash := response.GetClientDataJSONHash()
			t.Run(name, func(t *testing.T) {
				err = VerifyAttestationStatement(attestationObject, clientDataJSONHash)
				assert.NoError(t, err)
			})
		}
	})
}
