package webauthn

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

// VerifyPackedAttestationStatement verifies that an AttestationObject's attestation statement is valid according to the
// packed verification procedure.
func VerifyPackedAttestationStatement(
	attestationObject *AttestationObject,
	clientDataJSONHash ClientDataJSONHash,
) error {
	if attestationObject.Format != AttestationFormatPacked {
		return fmt.Errorf("%w: invalid format %s", ErrInvalidAttestationStatement, attestationObject.Format)
	}

	certificate, err := attestationObject.Statement.UnmarshalCertificate()
	if err == nil {
		// 2. If x5c is present:
		err = verifyPackedAttestationStatementCertificate(attestationObject, clientDataJSONHash, certificate)
	} else if errors.Is(err, ErrMissingCertificate) {
		// 3. If x5c is not present, self attestation is in use.
		err = verifyPackedAttestationStatementSelfAttestation(attestationObject, clientDataJSONHash)
	} else {
		return fmt.Errorf("%w: invalid certificate: %s", ErrInvalidAttestationStatement, err)
	}
	if err != nil {
		return err
	}

	return nil
}

func verifyPackedAttestationStatementCertificate(
	attestationObject *AttestationObject,
	clientDataJSONHash ClientDataJSONHash,
	certificate *x509.Certificate,
) error {
	// Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the
	// attestation public key in attestnCert with the algorithm specified in alg.
	alg := attestationObject.Statement.GetAlgorithm()

	// Verify that attestnCert meets the requirements in §8.2.1 Packed Attestation Statement Certificate
	// Requirements.

	// The attestation certificate MUST have the following fields/extensions:
	// - Version MUST be set to 3 (which is indicated by an ASN.1 INTEGER with value 2).
	if certificate.Version != 3 {
		return fmt.Errorf("%w: invalid certificate version", ErrInvalidCertificate)
	}
	// - Subject field MUST be set to:
	//   - Subject-C: ISO 3166 code specifying the country where the Authenticator vendor is incorporated
	//                (PrintableString)
	if len(certificate.Subject.Country) == 0 {
		return fmt.Errorf("%w: missing certificate country", ErrInvalidCertificate)
	}
	//   - Subject-O: Legal name of the Authenticator vendor (UTF8String)
	if len(certificate.Subject.Organization) == 0 {
		return fmt.Errorf("%w: missing certificate authenticator vendor name", ErrInvalidCertificate)
	}
	//   - Subject-OU: Literal string “Authenticator Attestation” (UTF8String)
	if strings.Join(certificate.Subject.OrganizationalUnit, "") != "Authenticator Attestation" {
		return fmt.Errorf("%w: invalid certificate organizational unit", ErrInvalidCertificate)
	}
	//   - Subject-CN: A UTF8String of the vendor’s choosing
	if len(certificate.Subject.CommonName) == 0 {
		return fmt.Errorf("%w: missing certificate common name", ErrInvalidCertificate)
	}
	// - If the related attestation root certificate is used for multiple authenticator models, the Extension OID
	//   1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present, containing the AAGUID as a 16-byte OCTET
	//   STRING. The extension MUST NOT be marked as critical.
	// - The Basic Constraints extension MUST have the CA component set to false.
	if certificate.IsCA == true {
		return fmt.Errorf("%w: certificate CA component must be set to false", ErrInvalidCertificate)
	}

	// If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the
	// value of this extension matches the aaguid in authenticatorData.

	// Optionally, inspect x5c and consult externally provided knowledge to determine whether attStmt conveys a Basic
	// or AttCA attestation.

	// If successful, return implementation-specific values representing attestation type Basic, AttCA or uncertainty,
	// and attestation trust path x5c.

	panic("not implemented")
}

func verifyPackedAttestationStatementSelfAttestation(
	attestationObject *AttestationObject,
	clientDataJSONHash ClientDataJSONHash,
) error {
	panic("not implemented")

}
