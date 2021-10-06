package webauthn

import (
	"crypto"
	"crypto/subtle"
	"fmt"

	"github.com/pomerium/webauthn/android"
	"github.com/pomerium/webauthn/cose"
)

// VerifyAndroidKeyAttestationStatement verifies that an AttestationObject's attestation statement is valid according to the
// android key verification procedure.
func VerifyAndroidKeyAttestationStatement(
	attestationObject *AttestationObject,
	clientDataJSONHash ClientDataJSONHash,
) error {
	certificates, err := attestationObject.Statement.UnmarshalCertificates()
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidAttestationStatement, err)
	}
	if len(certificates) < 1 {
		return fmt.Errorf("%w: missing x5c certificate", ErrInvalidAttestationStatement)
	}
	certificate := certificates[0]

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

	// Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
	// using the public key in the first certificate in x5c with the algorithm specified in alg.
	algorithm := attestationObject.Statement.GetAlgorithm()
	signature := attestationObject.Statement.GetSignature()
	verificationData := concat(attestationObject.AuthData, clientDataJSONHash[:])
	err = certificate.CheckSignature(
		algorithm.X509SignatureAlgorithm(),
		verificationData,
		signature,
	)
	if err != nil {
		return fmt.Errorf("%w: invalid signature, %s", ErrInvalidAttestationStatement, err)
	}

	// Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the
	// attestedCredentialData in authenticatorData.
	err = verifyAndroidKeyAttestationStatementCredentialPublicKey(
		certificate.PublicKey,
		publicKey.CryptoPublicKey(),
	)
	if err != nil {
		return err
	}

	// Verify that the attestationChallenge field in the attestation certificate extension data is
	// identical to clientDataHash.
	keyDescription, err := getCertificateAndroidKeyDescription(certificate)
	if err != nil {
		return fmt.Errorf("%w: invalid attestation certificate extension, %s", ErrInvalidAttestationStatement, err)
	}
	if subtle.ConstantTimeCompare(keyDescription.AttestationChallenge, clientDataJSONHash[:]) != 1 {
		return fmt.Errorf("%w: invalid attestation challenge", ErrInvalidAttestationStatement)
	}

	// Verify the following using the appropriate authorization list from the attestation certificate
	// extension data:
	// - The AuthorizationList.allApplications field is not present on either authorization list (softwareEnforced nor
	//   teeEnforced), since PublicKeyCredential MUST be scoped to the RP ID.
	if keyDescription.SoftwareEnforced.AllApplications ||
		keyDescription.TeeEnforced.AllApplications {
		return fmt.Errorf("%w: public key credential must be scoped to the RP id", ErrInvalidAttestationStatement)
	}

	// For the following, use only the teeEnforced authorization list if the RP wants to accept only keys
	// from a trusted execution environment, otherwise use the union of teeEnforced and softwareEnforced.

	// The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED.
	if keyDescription.TeeEnforced.Origin != android.KeyOriginGenerated {
		return fmt.Errorf("%w: public key credential must be generated", ErrInvalidAttestationStatement)
	}

	// The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN
	if !keyDescription.TeeEnforced.Purpose.Has(android.KeyMasterPurposeSign) {
		return fmt.Errorf("%w: public key credential must support signing", ErrInvalidAttestationStatement)
	}

	return nil
}

func verifyAndroidKeyAttestationStatementCredentialPublicKey(
	certificatePublicKey, credentialPublicKey crypto.PublicKey,
) error {
	withEqual, ok := certificatePublicKey.(interface {
		Equal(x crypto.PublicKey) bool
	})
	if !ok {
		return fmt.Errorf("%w: unsupported key type: %T", ErrInvalidAttestationStatement, certificatePublicKey)
	}

	if !withEqual.Equal(credentialPublicKey) {
		return fmt.Errorf("%w: mismatched public keys", ErrInvalidAttestationStatement)
	}
	return nil
}
