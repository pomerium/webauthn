package webauthn

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/pomerium/webauthn/cose"
)

var (
	// ErrInvalidAttestationStatement indicates that an attestation statement is invalid.
	ErrInvalidAttestationStatement = errors.New("invalid attestation statement")
	// ErrInvalidCertificate indicates that an attestation statement has an invalid x5c certificate.
	ErrInvalidCertificate = errors.New("invalid certificate")
	// ErrMissingCertificate indicates that an attestation statement is missing an x5c certificate.
	ErrMissingCertificate = errors.New("missing certificate")
)

// Attestation formats from https://www.w3.org/TR/webauthn-2/#sctn-defined-attestation-formats
const (
	AttestationFormatAndroidKey       = "android-key"
	AttestationFormatAndroidSafetyNet = "android-safetynet"
	AttestationFormatApple            = "apple"
	AttestationFormatFIDOU2F          = "fido-u2f"
	AttestationFormatNone             = "none"
	AttestationFormatPacked           = "packed"
	AttestationFormatTPM              = "tpm"
)

// Attestation types from https://www.w3.org/TR/webauthn-2/#sctn-attestation-types
const (
	// AttestationTypeBasic indicates the authenticator’s attestation key pair is specific to an authenticator "model",
	// i.e., a "batch" of authenticators. Thus, authenticators of the same, or similar, model often share the same
	// attestation key pair.
	AttestationTypeBasic = "Basic"
	// AttestationTypeSelf (also known as surrogate basic attestation) indicates the Authenticator does not have any
	// specific attestation key pair. Instead it uses the credential private key to create the attestation signature.
	// Authenticators without meaningful protection measures for an attestation private key typically use this
	// attestation type.
	AttestationTypeSelf = "Self"
	// AttestationTypeAttestationCA indicates an authenticator is based on a Trusted Platform Module (TPM) and holds an
	// authenticator-specific "endorsement key" (EK). This key is used to securely communicate with a trusted third
	// party, the Attestation CA (formerly known as a "Privacy CA"). The authenticator can generate multiple
	// attestation identity key pairs (AIK) and requests an Attestation CA to issue an AIK certificate for each. Using
	// this approach, such an authenticator can limit the exposure of the EK (which is a global correlation handle) to
	// Attestation CA(s). AIKs can be requested for each authenticator-generated public key credential individually,
	// and conveyed to Relying Parties as attestation certificates.
	AttestationTypeAttestationCA = "AttCA"
	// AttestationTypeAnonymizationCA indicates the authenticator uses an Anonymization CA which dynamically generates
	// per-credential attestation certificates such that the attestation statements presented to Relying Parties do
	// not provide uniquely identifiable information, e.g., that might be used for tracking purposes.
	AttestationTypeAnonymizationCA = "AnonCA"
	// AttestationTypeNone indicates no attestation information is available.
	AttestationTypeNone = "None"
)

// AttestationStatement is a map of data stored in an AttestationObject according to one of the pre-defined attestation
// statement formats.
type AttestationStatement map[string]interface{}

// GetAlgorithm gets the "alg" field of the attestation statement. If no field is found, or the field contains invalid
// data, 0 will be returned.
func (attestationStatement AttestationStatement) GetAlgorithm() cose.Algorithm {
	alg, _ := attestationStatement["alg"].(int64)
	return cose.Algorithm(alg)
}

// GetSignature gets the "sig" field of the attestation statement. It returns nil if no field is found, or the field
// does not contain a byte slice.
func (attestationStatement AttestationStatement) GetSignature() []byte {
	sig, _ := attestationStatement["sig"].([]byte)
	return sig
}

// UnmarshalCertificate unmarshals an X.509 certificate stored in an x5c key.
func (attestationStatement AttestationStatement) UnmarshalCertificate() (*x509.Certificate, error) {
	x5c, ok := attestationStatement["x5c"]
	if !ok {
		return nil, ErrMissingCertificate
	}

	if t, ok := x5c.([]interface{}); ok {
		x5c = t[0]
	}

	bs, ok := x5c.([]byte)
	if !ok {
		return nil, ErrInvalidCertificate
	}

	cert, err := x509.ParseCertificate(bs)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidCertificate, err)
	}

	return cert, nil
}

// VerifyAttestationStatement verifies that an AttestationObject's attestation statement is valid according to the
// verification procedures defined for know attestation statement formats.
func VerifyAttestationStatement(
	attestationObject *AttestationObject,
	clientDataJSONHash ClientDataJSONHash,
) error {
	switch attestationObject.Format {
	case AttestationFormatAndroidKey:
		return VerifyAndroidKeyAttestationStatement(attestationObject, clientDataJSONHash)
	case AttestationFormatApple:
		return VerifyAppleAttestationStatement(attestationObject, clientDataJSONHash)
	case AttestationFormatPacked:
		return VerifyPackedAttestationStatement(attestationObject, clientDataJSONHash)
	default:
		return fmt.Errorf("%w: unknown format %s", ErrInvalidAttestationStatement,
			attestationObject.Format)
	}
}
