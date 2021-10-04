package webauthn

import (
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"

	"github.com/pomerium/webauthn/cose"
)

// VerifyAppleAttestationStatement verifies that an AttestationObject's attestation statement is valid according to the
// packed verification procedure.
func VerifyAppleAttestationStatement(
	attestationObject *AttestationObject,
	clientDataJSONHash ClientDataJSONHash,
) error {
	// Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to
	// extract the contained fields.
	// - the attestationStatement has already been CBOR decoded by this point.

	certificate, err := attestationObject.Statement.UnmarshalCertificate()
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidAttestationStatement, err)
	}

	authenticatorData, err := attestationObject.UnmarshalAuthenticatorData()
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidAttestationStatement, err)
	}

	publicKey, _, err := cose.UnmarshalPublicKey(
		authenticatorData.AttestedCredentialData.CredentialPublicKey,
	)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidAttestationStatement, err)
	}

	// 2. Concatenate authenticatorData and clientDataHash to form nonceToHash.
	nonceToHash := concat(attestationObject.AuthData, clientDataJSONHash[:])

	// 3. Perform SHA-256 hash of nonceToHash to produce nonce.
	nonce := sha256.Sum256(nonceToHash)

	// 4. Verify that nonce equals the value of the extension with OID 1.2.840.113635.100.8.2 in credCert.
	certificateNonce, err := getCertificateAppleNonce(certificate)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidAttestationStatement, err)
	}
	if subtle.ConstantTimeCompare(nonce[:], certificateNonce) != 1 {
		return fmt.Errorf("%w: invalid nonce", ErrInvalidAttestationStatement)
	}

	// 5. Verify that the credential public key equals the Subject Public Key of credCert.
	return verifyAppleAttestationStatementCredentialPublicKey(
		certificate.PublicKey,
		publicKey,
	)
}

func verifyAppleAttestationStatementCredentialPublicKey(
	certificatePublicKey, credentialPublicKey crypto.PublicKey,
) error {
	withEqual, ok := certificatePublicKey.(interface {
		Equal(x crypto.PublicKey) bool
	})
	if !ok {
		return fmt.Errorf("%w: unsupported key type: %T", ErrInvalidAttestationStatement, certificatePublicKey)
	}

	if withEqual.Equal(credentialPublicKey) {
		return fmt.Errorf("%w: mismatched public keys", ErrInvalidAttestationStatement)
	}
	return nil
}
