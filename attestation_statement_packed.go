package webauthn

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/pomerium/webauthn/cose"
)

// VerifyPackedAttestationStatement verifies that an AttestationObject's attestation statement is valid according to the
// packed verification procedure.
func VerifyPackedAttestationStatement(
	attestationObject *AttestationObject,
	clientDataJSONHash ClientDataJSONHash,
) (*VerifyAttestationStatementResult, error) {
	if attestationObject.Format != AttestationFormatPacked {
		return nil, fmt.Errorf("%w: invalid format %s", ErrInvalidAttestationStatement, attestationObject.Format)
	}

	result := new(VerifyAttestationStatementResult)

	certificates, err := attestationObject.Statement.UnmarshalCertificates()
	if err == nil && len(certificates) > 0 {
		result.Type = AttestationTypeUnknown
		certificate := certificates[0]
		// 2. If x5c is present:
		err = verifyPackedAttestationStatementCertificate(attestationObject, clientDataJSONHash, certificate)
	} else if errors.Is(err, ErrMissingCertificate) {
		result.Type = AttestationTypeSelf
		// 3. If x5c is not present, self attestation is in use.
		err = verifyPackedAttestationStatementSelfAttestation(attestationObject, clientDataJSONHash)
	} else {
		return nil, fmt.Errorf("%w: invalid certificate: %s", ErrInvalidAttestationStatement, err)
	}
	if err != nil {
		return nil, err
	}
	result.TrustPaths = [][]*x509.Certificate{certificates}

	return result, nil
}

func verifyPackedAttestationStatementCertificate(
	attestationObject *AttestationObject,
	clientDataJSONHash ClientDataJSONHash,
	certificate *x509.Certificate,
) error {
	authenticatorData, err := attestationObject.UnmarshalAuthenticatorData()
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidAttestationStatement, err)
	}

	// Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the
	// attestation public key in attestnCert with the algorithm specified in alg.
	algorithm := attestationObject.Statement.GetAlgorithm()
	signature := attestationObject.Statement.GetSignature()
	verificationData := concat(attestationObject.AuthData, clientDataJSONHash[:])
	err = certificate.CheckSignature(algorithm.X509SignatureAlgorithm(), verificationData, signature)
	if err != nil {
		return fmt.Errorf("%w: invalid signature, %s", ErrInvalidAttestationStatement, err)
	}

	// Verify that attestnCert meets the requirements in §8.2.1 Packed Attestation Statement Certificate
	// Requirements.

	// The attestation certificate MUST have the following fields/extensions:
	// - Version MUST be set to 3 (which is indicated by an ASN.1 INTEGER with value 2).
	if certificate.Version != 3 {
		return fmt.Errorf("%w: invalid certificate version", ErrInvalidAttestationStatement)
	}
	// - Subject field MUST be set to:
	//   - Subject-C: ISO 3166 code specifying the country where the Authenticator vendor is incorporated
	//                (PrintableString)
	if strings.Join(certificate.Subject.Country, "") == "" {
		return fmt.Errorf("%w: missing certificate country", ErrInvalidAttestationStatement)
	}
	//   - Subject-O: Legal name of the Authenticator vendor (UTF8String)
	if strings.Join(certificate.Subject.Organization, "") == "" {
		return fmt.Errorf("%w: missing certificate authenticator vendor name", ErrInvalidAttestationStatement)
	}
	//   - Subject-OU: Literal string “Authenticator Attestation” (UTF8String)
	if strings.Join(certificate.Subject.OrganizationalUnit, "") != "Authenticator Attestation" {
		return fmt.Errorf("%w: invalid certificate organizational unit", ErrInvalidAttestationStatement)
	}
	//   - Subject-CN: A UTF8String of the vendor’s choosing
	if certificate.Subject.CommonName == "" {
		return fmt.Errorf("%w: missing certificate common name", ErrInvalidAttestationStatement)
	}
	// - The Basic Constraints extension MUST have the CA component set to false.
	if certificate.IsCA {
		return fmt.Errorf("%w: certificate CA component must be set to false", ErrInvalidAttestationStatement)
	}

	// If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the
	// value of this extension matches the aaguid in authenticatorData.
	aaguid, err := getCertificateAAGUID(certificate)
	if err == nil {
		if aaguid.Equals(authenticatorData.AttestedCredentialData.AAGUID) {
			return fmt.Errorf("%w: invalid AAGUID", ErrInvalidAttestationStatement)
		}
	} else if errors.Is(err, errMissingAAGUID) {
		// According to the spec:
		//
		//   If the related attestation root certificate is used for multiple authenticator models, the Extension OID
		//   1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present
		//
		// but its unclear how to know that this is the case. For now, we just ignore a missing AAGUID.
	} else {
		return fmt.Errorf("%w: %s", ErrInvalidCertificate, err)
	}

	return nil
}

func verifyPackedAttestationStatementSelfAttestation(
	attestationObject *AttestationObject,
	clientDataJSONHash ClientDataJSONHash,
) error {
	authenticatorData, err := attestationObject.UnmarshalAuthenticatorData()
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidCertificate, err)
	}

	publicKey, _, err := cose.UnmarshalPublicKey(authenticatorData.AttestedCredentialData.CredentialPublicKey)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidAttestationStatement, err)
	}

	// Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
	alg := attestationObject.Statement.GetAlgorithm()
	if alg != publicKey.Algorithm() {
		return fmt.Errorf("%w: unexpected algorithm for credential public key", ErrInvalidAttestationStatement)
	}

	// Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the
	// credential public key with alg.
	signature := attestationObject.Statement.GetSignature()
	verificationData := concat(attestationObject.AuthData, clientDataJSONHash[:])
	err = publicKey.Verify(verificationData, signature)
	if err != nil {
		return fmt.Errorf("%w: invalid signature, %s", ErrInvalidAttestationStatement, err)
	}

	return nil
}
