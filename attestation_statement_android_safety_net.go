package webauthn

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"fmt"

	"github.com/pomerium/webauthn/android"
	"github.com/square/go-jose/v3/jwt"
)

const safetyNetAttestationDNSName = "attest.android.com"

// VerifyAndroidSafetyNetAttestationStatement verifies that an AttestationObject's attestation statement is valid
// according to the android safetynet verification procedure.
func VerifyAndroidSafetyNetAttestationStatement(
	attestationObject *AttestationObject,
	clientDataJSONHash ClientDataJSONHash,
) error {
	// 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to
	//    extract the contained fields.
	//    - by this point the attestation statement is already CBOR decoded

	// 2. Verify that response is a valid SafetyNet response of version ver by following the steps indicated by the
	//    SafetyNet online documentation. As of this writing, there is only one format of the SafetyNet response and
	//    ver is reserved for future use.
	rawResponse, ok := attestationObject.Statement["response"].([]byte)
	if !ok {
		return fmt.Errorf("%w: missing SafetyNet response", ErrInvalidAttestationStatement)
	}

	safetyNetJWT, err := jwt.ParseSigned(string(rawResponse))
	if err != nil {
		return fmt.Errorf("%w: error parsing SafetyNet response, %s", ErrInvalidAttestationStatement, err)
	}

	chains, err := verifyAndroidSafetyNetCertificateChain(safetyNetJWT)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidAttestationStatement, err)
	}
	leaf := chains[0][0]

	var safetyNetClaims android.SafetyNetClaims
	err = safetyNetJWT.Claims(leaf.PublicKey, &safetyNetClaims)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidAttestationStatement, err)
	}

	// 3. Verify that the nonce attribute in the payload of response is identical to the Base64 encoding of the
	//    SHA-256 hash of the concatenation of authenticatorData and clientDataHash.
	verificationData := concat(attestationObject.AuthData, clientDataJSONHash[:])
	expectedNonce := sha256.Sum256(verificationData)
	if subtle.ConstantTimeCompare(safetyNetClaims.Nonce, expectedNonce[:]) != 1 {
		return fmt.Errorf("%w: invalid nonce", ErrInvalidAttestationStatement)
	}

	// 4. Verify that the SafetyNet response actually came from the SafetyNet service by following the steps in the
	//    SafetyNet online documentation.
	//    - certificates are verified by verifyAndroidSafetyNetCertificateChain

	return nil
}

func verifyAndroidSafetyNetCertificateChain(safetyNetJWT *jwt.JSONWebToken) (chains [][]*x509.Certificate, err error) {
	// Validate the SSL certificate chain and use SSL hostname matching to verify that the leaf certificate was issued
	// to the hostname attest.android.com.
	for _, header := range safetyNetJWT.Headers {
		headerChains, err := header.Certificates(x509.VerifyOptions{
			DNSName: safetyNetAttestationDNSName,
		})
		if err != nil {
			return nil, err
		}
		chains = append(chains, headerChains...)
	}

	if len(chains) == 0 || len(chains[0]) == 0 {
		return nil, ErrInvalidCertificate
	}

	return chains, nil
}
