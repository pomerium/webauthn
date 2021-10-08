package webauthn

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFIDOMetadataServiceTrustAnchorProvider(t *testing.T) {
	response := readTestAuthenticatorAttestationResponse(t, "U2F")
	attestationObject, err := response.UnmarshalAttestationObject()
	require.NoError(t, err)
	authenticatorData, err := attestationObject.UnmarshalAuthenticatorData()
	require.NoError(t, err)

	provider := NewFIDOMetadataServiceTrustAnchorProvider()
	trustAnchors, err := provider.GetTrustAnchors(context.Background(),
		AttestationFormatFIDOU2F,
		AttestationTypeBasic,
		authenticatorData.AttestedCredentialData.AAGUID,
	)
	assert.NoError(t, err)
	assert.NotNil(t, trustAnchors)

}
