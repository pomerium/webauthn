package webauthn

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/pomerium/webauthn/cose"
	"github.com/pomerium/webauthn/tpm"
)

var (
	// ErrInvalidAttestationStatement indicates that an attestation statement is invalid.
	ErrInvalidAttestationStatement = errors.New("invalid attestation statement")
	// ErrInvalidCertificate indicates that an attestation statement has an invalid x5c certificate.
	ErrInvalidCertificate = errors.New("invalid certificate")
	// ErrInvalidCertInfo indicates that an attestation statement has an invalid certInfo field.
	ErrInvalidCertInfo = errors.New("invalid certInfo")
	// ErrInvalidPubArea indicates that an attestation statement has an invalid pubArea field.
	ErrInvalidPubArea = errors.New("invalid pubArea")
	// ErrMissingCertificates indicates that an attestation statement is missing x5c certificates.
	ErrMissingCertificates = errors.New("missing certificates")
	// ErrMissingCertInfo indicates that an attestation statement is missing the certInfo field.
	ErrMissingCertInfo = errors.New("missing certInfo")
	// ErrMissingPubArea indicates that an attestation statement is missing a pubArea field.
	ErrMissingPubArea = errors.New("missing pubArea")
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

// AttestationType is one of the types from https://www.w3.org/TR/webauthn-2/#sctn-attestation-types.
type AttestationType string

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

// UnmarshalCertificate unmarshals X.509 certificates stored in an x5c key.
func (attestationStatement AttestationStatement) UnmarshalCertificates() ([]*x509.Certificate, error) {
	x5c, ok := attestationStatement["x5c"]
	if !ok {
		return nil, ErrMissingCertificates
	}

	x5cs, ok := x5c.([]interface{})
	if !ok {
		return nil, ErrInvalidCertificate
	}

	var certificates []*x509.Certificate
	for _, x5c := range x5cs {
		bs, ok := x5c.([]byte)
		if !ok {
			return nil, ErrInvalidCertificate
		}

		certificate, err := x509.ParseCertificate(bs)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidCertificate, err)
		}
		certificates = append(certificates, certificate)
	}

	return certificates, nil
}

// UnmarshalCertInfo unmarshals the TPM certInfo from an attestation statement.
func (attestationStatement AttestationStatement) UnmarshalCertInfo() (*tpm.AttestationData, error) {
	certInfo, ok := attestationStatement["certInfo"]
	if !ok {
		return nil, ErrMissingCertInfo
	}

	bs, ok := certInfo.([]byte)
	if !ok {
		return nil, ErrInvalidCertInfo
	}

	attestationData, err := tpm.UnmarshalAttestationData(bs)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidCertInfo, err)
	}

	return attestationData, nil
}

// UnmarshalPubArea unmarshals the pubArea field from the attestation statement.
func (attestationStatement AttestationStatement) UnmarshalPubArea() (*tpm.Public, error) {
	pubArea, ok := attestationStatement["pubArea"]
	if !ok {
		return nil, ErrMissingPubArea
	}

	bs, ok := pubArea.([]byte)
	if !ok {
		return nil, ErrInvalidPubArea
	}

	public, err := tpm.UnmarshalPublic(bs)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidPubArea, err)
	}

	return public, nil
}

// VerifyAttestationStatementResult is the result of running the verify attestation statement procedure.
// Based on the attestation type and the relying parties requirements the `TrustPath` can be verified
// for trustworthiness against a set of root certificates.
type VerifyAttestationStatementResult struct {
	Type      AttestationType
	TrustPath []*x509.Certificate
}

// VerifyAttestationStatement verifies that an AttestationObject's attestation statement is valid according to the
// verification procedures defined for know attestation statement formats.
func VerifyAttestationStatement(
	attestationObject *AttestationObject,
	clientDataJSONHash ClientDataJSONHash,
) (*VerifyAttestationStatementResult, error) {
	switch attestationObject.Format {
	case AttestationFormatPacked:
		return VerifyPackedAttestationStatement(attestationObject, clientDataJSONHash)
	case AttestationFormatTPM:
		return VerifyTPMAttestationStatement(attestationObject, clientDataJSONHash)
	default:
		return nil, fmt.Errorf("%w: unknown format %s", ErrInvalidAttestationStatement,
			attestationObject.Format)
	}
}
