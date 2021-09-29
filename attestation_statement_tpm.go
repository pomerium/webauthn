package webauthn

import (
	"crypto/x509"
	"fmt"

	"github.com/pomerium/webauthn/tpm"
)

func VerifyTPMAttestationStatement(
	attestationObject *AttestationObject,
	clientDataJSONHash ClientDataJSONHash,
) error {
	// Verify that the public key specified by the parameters and unique fields of pubArea is identical to the
	// credentialPublicKey in the attestedCredentialData in authenticatorData.

	// Concatenate authenticatorData and clientDataHash to form attToBeSigned.
	//
	//Validate that certInfo is valid:
	//
	//Verify that magic is set to TPM_GENERATED_VALUE.
	//
	//Verify that type is set to TPM_ST_ATTEST_CERTIFY.
	//
	//Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
	//
	//Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in [TPMv2-Part2] section 10.12.3, whose name field contains a valid Name for pubArea, as computed using the algorithm in the nameAlg field of pubArea using the procedure specified in [TPMv2-Part1] section 16.
	//
	//Verify that x5c is present.
	//
	//Note that the remaining fields in the "Standard Attestation Structure" [TPMv2-Part1] section 31.2, i.e., qualifiedSigner, clockInfo and firmwareVersion are ignored. These fields MAY be used as an input to risk engines.
	//
	//Verify the sig is a valid signature over certInfo using the attestation public key in aikCert with the algorithm specified in alg.
	//
	//Verify that aikCert meets the requirements in § 8.3.1 TPM Attestation Statement Certificate Requirements.
	//
	//If aikCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData.
	//

	return nil
}

func verifyTPMAttestationStatementCertificateRequirements(
	attestationObject *AttestationObject,
	clientDataJSONHash ClientDataJSONHash,
	certificate *x509.Certificate,
) error {
	// Version MUST be set to 3.
	if certificate.Version != 3 {
		return fmt.Errorf("%w: invalid certificate version", ErrInvalidAttestationStatement)
	}

	// Subject field MUST be set to empty.
	if len(certificate.RawSubject) > 0 {
		return fmt.Errorf("%w: certificate subject must be empty", ErrInvalidAttestationStatement)
	}

	// The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.
	_, err := tpm.GetHardwareDetailsFromCertificate(certificate)
	if err != nil {
		return fmt.Errorf("%w: invalid certificate SAN: %s", ErrInvalidAttestationStatement, err)
	}

	// The Extended Key Usage extension MUST contain the OID 2.23.133.8.3.
	if !certificateHasAIK(certificate) {
		return fmt.Errorf("%w: missing certificate AIK extended key usage", ErrInvalidAttestationStatement)
	}

	// The Basic Constraints extension MUST have the CA component set to false.
	if certificate.IsCA {
		return fmt.Errorf("%w: certificate must have CA set to false", ErrInvalidAttestationStatement)
	}

	return nil
}
