package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"

	"github.com/pomerium/webauthn/android"
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
		attestationObject := createTestAndroidKeyAttestationObject(t,
			[]byte{0, 0, 0, 0}, nil, nil)
		attestationObject.Statement["sig"] = []byte("INVALID")
		err := VerifyAttestationStatement(attestationObject, ClientDataJSONHash{})
		assert.Contains(t, err.Error(), "invalid signature")
	})
	t.Run("mismatched keys", func(t *testing.T) {
		attestationObject := createTestAndroidKeyAttestationObject(t,
			[]byte{0, 0, 0, 0}, nil,
			func(authenticatorData *AuthenticatorData) {
				newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)

				key, err := cose.NewECDSAPublicKey(cose.AlgorithmES256, newKey.PublicKey)
				require.NoError(t, err)

				rawKey, err := key.Marshal()
				require.NoError(t, err)

				authenticatorData.AttestedCredentialData.CredentialPublicKey = rawKey
			})
		err := VerifyAttestationStatement(attestationObject, ClientDataJSONHash{})
		assert.Contains(t, err.Error(), "mismatched public keys")
	})
	t.Run("different challenges", func(t *testing.T) {
		attestationObject := createTestAndroidKeyAttestationObject(t,
			[]byte{0, 0, 0, 0},
			func(kdp *android.KeyDescription) {
				kdp.AttestationChallenge = []byte{
					1, 2, 3, 4, 5, 6, 7, 8,
					1, 2, 3, 4, 5, 6, 7, 8,
					1, 2, 3, 4, 5, 6, 7, 8,
					1, 2, 3, 4, 5, 6, 7, 8,
				}
			}, nil)
		err := VerifyAttestationStatement(attestationObject, ClientDataJSONHash{})
		assert.Contains(t, err.Error(), "invalid attestation challenge")
	})
	t.Run("allows all applications", func(t *testing.T) {
		attestationObject := createTestAndroidKeyAttestationObject(t,
			[]byte{0, 0, 0, 0},
			func(kdp *android.KeyDescription) {
				kdp.TeeEnforced.AllApplications = true
			}, nil)
		err := VerifyAttestationStatement(attestationObject, ClientDataJSONHash{})
		assert.Contains(t, err.Error(), "must be scoped")
	})
	t.Run("wrong origin", func(t *testing.T) {
		attestationObject := createTestAndroidKeyAttestationObject(t,
			[]byte{0, 0, 0, 0},
			func(kdp *android.KeyDescription) {
				kdp.TeeEnforced.Origin = android.KeyOriginImported
			}, nil)
		err := VerifyAttestationStatement(attestationObject, ClientDataJSONHash{})
		assert.Contains(t, err.Error(), "must be generated")
	})
	t.Run("wrong purpose", func(t *testing.T) {
		attestationObject := createTestAndroidKeyAttestationObject(t,
			[]byte{0, 0, 0, 0},
			func(kdp *android.KeyDescription) {
				kdp.TeeEnforced.Purpose = android.KeyMasterPurposeSet{android.KeyMasterPurposeEncrypt}
			}, nil)
		err := VerifyAttestationStatement(attestationObject, ClientDataJSONHash{})
		assert.Contains(t, err.Error(), "must support signing")
	})
}

func createTestAndroidKeyAttestationObject(
	t *testing.T,
	rpID []byte,
	modifyKDP func(kdp *android.KeyDescription),
	modifyAuthenticatorData func(data *AuthenticatorData),
) *AttestationObject {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	kdp := &android.KeyDescription{
		AttestationChallenge: make([]byte, 32),
		SoftwareEnforced:     android.AuthorizationList{},
		TeeEnforced: android.AuthorizationList{
			Purpose: android.KeyMasterPurposeSet{android.KeyMasterPurposeSign},
		},
	}
	if modifyKDP != nil {
		modifyKDP(kdp)
	}
	rawKDP, err := kdp.Marshal()
	require.NoError(t, err)

	x5ctpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		SubjectKeyId:       generateSubjectKeyID(t, privateKey.Public()),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{Id: oidAndroidKey, Value: rawKDP},
		},
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
	if modifyAuthenticatorData != nil {
		modifyAuthenticatorData(authenticatorData)
	}
	rawAuthenticatorData, err := authenticatorData.Marshal()
	require.NoError(t, err)

	verificationData := concat(rawAuthenticatorData, make([]byte, 32))
	hashData := sha256.Sum256(verificationData)
	rawSignature, err := ecdsa.SignASN1(rand.Reader, privateKey, hashData[:])
	require.NoError(t, err)

	return &AttestationObject{
		AuthData: rawAuthenticatorData,
		Format:   AttestationFormatAndroidKey,
		Statement: AttestationStatement{
			"alg": int64(cose.AlgorithmES256),
			"sig": rawSignature,
			"x5c": []interface{}{
				x5c,
			},
		},
	}
}

func generateSubjectKeyID(t *testing.T, pub crypto.PublicKey) []byte {
	b, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	hash := sha256.Sum256(b)
	return hash[:]
}
