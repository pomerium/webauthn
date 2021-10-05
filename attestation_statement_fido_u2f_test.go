package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"testing"

	"github.com/pomerium/webauthn/cose"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyFIDOU2FAttestationStatement(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, name := range []string{"U2F"} {
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

	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key2, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	t.Run("missing x5c", func(t *testing.T) {
		attestationObject := createTestFIDOU2FAttestationObject(t,
			[]byte{0, 0, 0, 0},
			key1,
			nil,
		)
		attestationObject.Statement["x5c"] = nil
		err := VerifyAttestationStatement(attestationObject, ClientDataJSONHash{})
		assert.Contains(t, err.Error(), "invalid x5c certificate")
	})
	t.Run("bad algorithm", func(t *testing.T) {
		attestationObject := createTestFIDOU2FAttestationObject(t,
			[]byte{0, 0, 0, 0},
			key2,
			nil,
		)
		err = VerifyAttestationStatement(attestationObject, ClientDataJSONHash{})
		assert.Contains(t, err.Error(), "only the P-256 curve is supported")
	})
	t.Run("bad public key", func(t *testing.T) {
		key, err := cose.NewRSAPublicKey(cose.AlgorithmRS256, rsaKey.PublicKey)
		require.NoError(t, err)

		rawKey, err := key.Marshal()
		require.NoError(t, err)

		attestationObject := createTestFIDOU2FAttestationObject(t,
			[]byte{0, 0, 0, 0},
			key1,
			func(data *AuthenticatorData) {
				data.AttestedCredentialData.CredentialPublicKey = rawKey
			},
		)
		err = VerifyAttestationStatement(attestationObject, ClientDataJSONHash{})
		assert.Contains(t, err.Error(), "only ECDSA keys are supported")
	})
	t.Run("bad signature", func(t *testing.T) {
		attestationObject := createTestFIDOU2FAttestationObject(t,
			[]byte{0, 0, 0, 0},
			key1,
			nil,
		)
		attestationObject.Statement["sig"] = nil
		err := VerifyAttestationStatement(attestationObject, ClientDataJSONHash{})
		assert.Contains(t, err.Error(), "invalid signature")
	})
}

func createTestFIDOU2FAttestationObject(
	t *testing.T,
	rpID []byte,
	privateKey *ecdsa.PrivateKey,
	modifyAuthenticatorData func(data *AuthenticatorData),
) *AttestationObject {
	x5ctpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		SubjectKeyId:       generateSubjectKeyID(t, privateKey.Public()),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		KeyUsage:           x509.KeyUsageDigitalSignature,
	}
	x5c, err := x509.CreateCertificate(rand.Reader, x5ctpl, x5ctpl, privateKey.Public(), privateKey)
	require.NoError(t, err)

	key, err := cose.NewECDSAPublicKey(cose.AlgorithmES256, privateKey.PublicKey)
	require.NoError(t, err)
	publicKeyU2F := key.RawX962ECC()

	rawKey, err := key.Marshal()
	require.NoError(t, err)

	rpIDHash := sha256.Sum256(rpID)
	authenticatorData := &AuthenticatorData{
		RPIDHash:  rpIDHash,
		Flags:     authenticatorFlagsAT,
		SignCount: 0,
		AttestedCredentialData: &AttestedCredentialData{
			AAGUID:              newRandomAAGUID(),
			CredentialID:        []byte{},
			CredentialPublicKey: rawKey,
		},
		Extensions: []byte{},
	}
	if modifyAuthenticatorData != nil {
		modifyAuthenticatorData(authenticatorData)
	}
	rawAuthenticatorData, err := authenticatorData.Marshal()
	require.NoError(t, err)

	verificationData := concat([]byte{0x00},
		rpIDHash[:],
		make([]byte, 32),
		authenticatorData.AttestedCredentialData.CredentialID,
		publicKeyU2F[:],
	)
	hashData := sha256.Sum256(verificationData)

	rawSignature, err := ecdsa.SignASN1(rand.Reader, privateKey, hashData[:])
	require.NoError(t, err)

	return &AttestationObject{
		AuthData: rawAuthenticatorData,
		Format:   AttestationFormatFIDOU2F,
		Statement: AttestationStatement{
			"sig": rawSignature,
			"x5c": []interface{}{
				x5c,
			},
		},
	}
}
