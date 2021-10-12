package webauthn

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFIDOMetadataServiceTrustAnchorProvider(t *testing.T) {
	response := readTestAuthenticatorAttestationResponse(t, "GoogleTitan")
	attestationObject, err := response.UnmarshalAttestationObject()
	require.NoError(t, err)
	authenticatorData, err := attestationObject.UnmarshalAuthenticatorData()
	require.NoError(t, err)
	clientData, err := response.UnmarshalClientData()
	require.NoError(t, err)

	bs, _ := json.Marshal(attestationObject)
	t.Error(string(bs))

	bs, _ = json.Marshal(authenticatorData)
	t.Error(string(bs))

	bs, _ = json.Marshal(clientData)
	t.Error(string(bs))

	provider := NewFIDOMetadataServiceTrustAnchorProvider()
	trustAnchors, err := provider.GetTrustAnchors(context.Background(),
		AttestationFormatFIDOU2F,
		AttestationTypeBasic,
		authenticatorData.AttestedCredentialData.AAGUID,
	)
	assert.NoError(t, err)
	assert.NotNil(t, trustAnchors)

}
