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

		certs, err := attestationObject.Statement.UnmarshalCertificates()
		assert.NoError(t, err)
		assert.Equal(t,
			"CN=FT BioPass FIDO2 USB,OU=Authenticator Attestation,O=Feitian Technologies,C=CN",
			certs[0].Subject.String())
	})
	t.Run("missing x5c", func(t *testing.T) {
		_, err := AttestationStatement{}.UnmarshalCertificates()
		assert.ErrorIs(t, err, ErrMissingCertificates)
	})
	t.Run("invalid x5c", func(t *testing.T) {
		_, err := AttestationStatement{
			"x5c": "NOT_A_CERTIFICATE",
		}.UnmarshalCertificates()
		assert.ErrorIs(t, err, ErrInvalidCertificate)
		_, err = AttestationStatement{
			"x5c": []byte("NOT_A_CERTIFICATE"),
		}.UnmarshalCertificates()
		assert.ErrorIs(t, err, ErrInvalidCertificate)
	})
}
