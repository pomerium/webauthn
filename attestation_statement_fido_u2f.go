package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"

	"github.com/pomerium/webauthn/cose"
)

// VerifyFIDOU2FAttestationStatement verifies a fido-u2f formatted attestation statement according to procedure
// documented here: https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation.
func VerifyFIDOU2FAttestationStatement(
	attestationObject *AttestationObject,
	clientDataJSONHash ClientDataJSONHash,
) error {
	// 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to
	//    extract the contained fields.
	//    - by this point the attestation statement has already been CBOR decoded

	// 2. Check that x5c has exactly one element and let attCert be that element. Let certificate public key be the
	//    public key conveyed by attCert. If certificate public key is not an Elliptic Curve (EC) public key over the
	//    P-256 curve, terminate this algorithm and return an appropriate error.
	certificate, err := attestationObject.Statement.UnmarshalCertificate()
	if err != nil {
		return fmt.Errorf("%w: invalid x5c certificate: %s", ErrInvalidAttestationStatement, err)
	}
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: invalid x5c certificate, only ECDSA keys are supported", ErrInvalidAttestationStatement)
	}
	if publicKey.Curve != elliptic.P256() {
		return fmt.Errorf("%w: invalid x5c certificate, only the P-256 curve is supported",
			ErrInvalidAttestationStatement)
	}

	// 3. Extract the claimed rpIdHash from authenticatorData, and the claimed credentialId and credentialPublicKey from
	//    authenticatorData.attestedCredentialData.
	authenticatorData, err := attestationObject.UnmarshalAuthenticatorData()
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidAttestationStatement, err)
	}
	rpIDHash := authenticatorData.RPIDHash
	credentialID := authenticatorData.AttestedCredentialData.CredentialID

	// 4. Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of [RFC8152]) to Raw ANSI X9.62 public key
	//    format (see ALG_KEY_ECC_X962_RAW in Section 3.6.2 Public Key Representation Formats of [FIDO-Registry]).
	credentialPublicKey, _, err := cose.UnmarshalPublicKey(authenticatorData.AttestedCredentialData.CredentialPublicKey)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidAttestationStatement, err)
	}

	//    4a. Let x be the value corresponding to the "-2" key (representing x coordinate) in credentialPublicKey, and
	//        confirm its size to be of 32 bytes. If size differs or "-2" key is not found, terminate this algorithm and
	//        return an appropriate error.

	//    4b. Let y be the value corresponding to the "-3" key (representing y coordinate) in credentialPublicKey, and
	//        confirm its size to be of 32 bytes. If size differs or "-3" key is not found, terminate this algorithm and
	//        return an appropriate error.
	ecdsaKey, ok := credentialPublicKey.(*cose.ECDSAPublicKey)
	if !ok {
		return fmt.Errorf("%w: only ECDSA keys are supported", ErrInvalidAttestationStatement)
	}
	//    4c. Let publicKeyU2F be the concatenation 0x04 || x || y.
	publicKeyU2F := ecdsaKey.RawX962ECC()

	// 5. Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId ||
	//    publicKeyU2F) (see Section 4.3 of [FIDO-U2F-Message-Formats]).
	verificationData := concat(
		[]byte{0x00},
		rpIDHash[:],
		clientDataJSONHash[:],
		credentialID,
		publicKeyU2F[:],
	)

	// 6. Verify the sig using verificationData and the certificate public key per section 4.1.4 of [SEC1] with SHA-256
	//    as the hash function used in step two.
	signature := attestationObject.Statement.GetSignature()
	err = certificate.CheckSignature(
		credentialPublicKey.Algorithm().X509SignatureAlgorithm(),
		verificationData,
		signature,
	)
	if err != nil {
		return fmt.Errorf("%w: invalid signature, %s", ErrInvalidAttestationStatement, err)
	}

	return nil
}
