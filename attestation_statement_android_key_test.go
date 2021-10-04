package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"testing"

	"github.com/pomerium/webauthn/cose"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyAndroidKeyAttestationStatement(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, name := range []string{"AndroidKey"} {
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
	t.Run("bad signature", func(t *testing.T) {
		attestationObject := createTestAndroidKeyAttestationObject(t, []byte{0, 0, 0, 0})
		err := VerifyAttestationStatement(attestationObject, ClientDataJSONHash{})
		assert.NoError(t, err)
	})
	t.Run("mismatched keys", func(t *testing.T) {})
	t.Run("different challenges", func(t *testing.T) {})
	t.Run("allows all applications", func(t *testing.T) {})
	t.Run("wrong origin", func(t *testing.T) {})
	t.Run("wrong purpose", func(t *testing.T) {})
}

func createTestAndroidKeyAttestationObject(
	t *testing.T,
	rpID []byte,
) *AttestationObject {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	x5ctpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	x5c, err := x509.CreateCertificate(rand.Reader, x5ctpl, x5ctpl, privateKey.Public(), privateKey)
	require.NoError(t, err)

	key, err := cose.NewECDSAPublicKey(cose.AlgorithmES256, privateKey.PublicKey)
	require.NoError(t, err)

	rawKey, err := key.Marshal()
	require.NoError(t, err)

	authenticatorData := &AuthenticatorData{
		RPIDHash:  sha256.Sum256(rpID),
		Flags:     authenticatorFlagsAT,
		SignCount: 0,
		AttestedCredentialData: &AttestedCredentialData{
			AAGUID:              newRandomAAGUID(),
			CredentialID:        []byte{},
			CredentialPublicKey: rawKey,
		},
		Extensions: []byte{},
	}
	rawAuthenticatorData, err := authenticatorData.Marshal()
	require.NoError(t, err)
	return &AttestationObject{
		AuthData: rawAuthenticatorData,
		Format:   AttestationFormatAndroidKey,
		Statement: AttestationStatement{
			"alg": cose.AlgorithmES256,
			"sig": []byte{},
			"x5c": []interface{}{
				x5c,
			},
		},
	}
}
