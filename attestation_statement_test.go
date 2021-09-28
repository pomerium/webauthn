package webauthn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttestationStatement_UnmarshalCertificate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		response := readTestAuthenticatorAttestationResponse(t, "Packed")
		attestationObject, err := response.UnmarshalAttestationObject()
		require.NoError(t, err)

		cert, err := attestationObject.Statement.UnmarshalCertificate()
		assert.NoError(t, err)
		assert.Equal(t,
			"CN=FT BioPass FIDO2 USB,OU=Authenticator Attestation,O=Feitian Technologies,C=CN",
			cert.Subject.String())
	})
	t.Run("missing x5c", func(t *testing.T) {
		_, err := AttestationStatement{}.UnmarshalCertificate()
		assert.ErrorIs(t, err, ErrMissingCertificate)
	})
	t.Run("invalid x5c", func(t *testing.T) {
		_, err := AttestationStatement{
			"x5c": "NOT_A_CERTIFICATE",
		}.UnmarshalCertificate()
		assert.ErrorIs(t, err, ErrInvalidCertificate)
		_, err = AttestationStatement{
			"x5c": []byte("NOT_A_CERTIFICATE"),
		}.UnmarshalCertificate()
		assert.ErrorIs(t, err, ErrInvalidCertificate)
	})
}
