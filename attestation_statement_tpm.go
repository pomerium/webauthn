package webauthn

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/pomerium/webauthn/tpm"
)

// VerifyTPMAttestationStatement verifies a TPM attestation statement for correctness.
func VerifyTPMAttestationStatement(
	attestationObject *AttestationObject,
	clientDataJSONHash ClientDataJSONHash,
) (*VerifyAttestationStatementResult, error) {
	aikCerts, err := attestationObject.Statement.UnmarshalCertificates()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidAttestationStatement, err)
	}

	tpmCertInfo, err := attestationObject.Statement.UnmarshalCertInfo()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidAttestationStatement, err)
	}

	tpmPubArea, err := attestationObject.Statement.UnmarshalPubArea()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidAttestationStatement, err)
	}

	// Verify that the public key specified by the parameters and unique fields of pubArea is identical to the
	// credentialPublicKey in the attestedCredentialData in authenticatorData.
	err = verifyTPMAttestationStatementPubAreaMatches(
		aikCerts,
		tpmPubArea,
	)
	if err != nil {
		return nil, err
	}

	// Validate that certInfo is valid
	err = verifyTPMAttestationStatementCertInfo(
		attestationObject,
		clientDataJSONHash,
		aikCerts,
		tpmPubArea,
		tpmCertInfo,
	)
	if err != nil {
		return nil, err
	}

	// Verify the attestation statement certificate requirements
	err = verifyTPMAttestationStatementCertificateRequirements(
		aikCerts,
	)
	if err != nil {
		return nil, err
	}

	return &VerifyAttestationStatementResult{
		Type:       AttestationTypeAttestationCA,
		TrustPaths: [][]*x509.Certificate{aikCerts},
	}, nil
}

func verifyTPMAttestationStatementCertificateRequirements(
	certificates []*x509.Certificate,
) error {
	if len(certificates) == 0 {
		return fmt.Errorf("%w: missing aik certificate", ErrInvalidAttestationStatement)
	}
	certificate := certificates[0]

	// Version MUST be set to 3.
	if certificate.Version != 3 {
		return fmt.Errorf("%w: invalid certificate version", ErrInvalidAttestationStatement)
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

func verifyTPMAttestationStatementCertInfo(
	attestationObject *AttestationObject,
	clientDataJSONHash ClientDataJSONHash,
	aikCerts []*x509.Certificate,
	tpmPubArea *tpm.Public,
	tpmCertInfo *tpm.AttestationData,
) error {
	// Verify that magic is set to TPM_GENERATED_VALUE.
	if tpmCertInfo.Magic != tpm.GeneratedValue {
		return fmt.Errorf("%w: invalid tpm magic number", ErrInvalidAttestationStatement)
	}

	// Verify that type is set to TPM_ST_ATTEST_CERTIFY.
	if tpmCertInfo.Type != tpm.TagAttestCertify {
		return fmt.Errorf("%w: invalid tpm attestation type", ErrInvalidAttestationStatement)
	}

	// Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
	attToBeSigned := concat(attestationObject.AuthData, clientDataJSONHash[:])
	alg := attestationObject.Statement.GetAlgorithm()
	if !hashIsEqual(alg.Hash(), attToBeSigned, tpmCertInfo.ExtraData) {
		return fmt.Errorf("%w: invalid tpm extraData hash", ErrInvalidAttestationStatement)
	}

	// Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in [TPMv2-Part2] section
	// 10.12.3, whose name field contains a valid Name for pubArea, as computed using the algorithm in the
	// nameAlg field of pubArea using the procedure specified in [TPMv2-Part1] section 16.
	bs, err := tpmPubArea.Encode()
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidAttestationStatement, err)
	}

	ch, err := tpmCertInfo.AttestedCertifyInfo.Name.Digest.Alg.Hash()
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidAttestationStatement, err)
	}
	if !hashIsEqual(ch, bs, tpmCertInfo.AttestedCertifyInfo.Name.Digest.Value) {
		return fmt.Errorf("%w: invalid certify info name", ErrInvalidAttestationStatement)
	}

	// Verify the sig is a valid signature over certInfo using the attestation public key in aikCert
	// with the algorithm specified in alg.
	bs, err = tpmCertInfo.Encode()
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidAttestationStatement, err)
	}

	if len(aikCerts) == 0 {
		return fmt.Errorf("%w: missing aik cert", ErrInvalidAttestationStatement)
	}
	aikCert := aikCerts[0]

	signature := attestationObject.Statement.GetSignature()
	err = aikCert.CheckSignature(alg.X509SignatureAlgorithm(), bs, signature)
	if err != nil {
		return fmt.Errorf("%w: invalid certInfo signature: %s", ErrInvalidAttestationStatement, err)
	}

	return nil
}

func verifyTPMAttestationStatementPubAreaMatches(
	certificates []*x509.Certificate,
	tpmPubArea *tpm.Public,
) error {
	checkCertificate := func(certificate *x509.Certificate) error {
		certificateKey := certificate.PublicKey
		tpmPubAreaKey, err := tpmPubArea.Key()
		if err != nil {
			return fmt.Errorf("%w: error getting tpm pub area key: %s", ErrInvalidAttestationStatement, err)
		}

		switch certificateKey := certificateKey.(type) {
		case *rsa.PublicKey:
			tpmPubAreaKey, ok := tpmPubAreaKey.(*rsa.PublicKey)
			if !ok {
				return fmt.Errorf("%w: invalid public keys", ErrInvalidAttestationStatement)
			}

			if certificateKey.E != tpmPubAreaKey.E {
				return fmt.Errorf("%w: mismatched public keys", ErrInvalidAttestationStatement)
			}
		case *ecdsa.PublicKey:
			tpmPubAreaKey, ok := tpmPubAreaKey.(*ecdsa.PublicKey)
			if !ok {
				return fmt.Errorf("%w: invalid public keys", ErrInvalidAttestationStatement)
			}

			if certificateKey.Curve != tpmPubAreaKey.Curve ||
				certificateKey.X.Cmp(tpmPubAreaKey.X) != 0 ||
				certificateKey.Y.Cmp(tpmPubAreaKey.Y) != 0 {
				return fmt.Errorf("%w: mismatched public keys", ErrInvalidAttestationStatement)
			}

		default:
			return fmt.Errorf("%w: unsupported key format", ErrInvalidAttestationStatement)
		}

		return nil
	}

	err := ErrInvalidCertificate
	for _, certificate := range certificates {
		err = checkCertificate(certificate)
		if err == nil {
			return nil
		}
	}

	return err
}
