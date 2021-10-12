package webauthn

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/pomerium/webauthn/cose"
)

// The PublicKeyCredentialCreationOptions supplies create() with the data it needs to generate a new credential.
type PublicKeyCredentialCreationOptions struct {
	// This member contains data about the Relying Party responsible for the request.
	//
	// Its value’s name member is REQUIRED.
	//
	// Its value’s id member specifies the RP ID the credential should be scoped to. If omitted, its value will be
	// the CredentialsContainer object’s relevant settings object's origin's effective domain.
	RP PublicKeyCredentialRpEntity `json:"rp"`
	// This member contains data about the user account for which the Relying Party is requesting attestation.
	//
	// Its value’s name, displayName and id members are REQUIRED.
	User PublicKeyCredentialUserEntity `json:"user"`
	// This member contains a challenge intended to be used for generating the newly created credential’s
	// attestation object.
	Challenge []byte `json:"challenge"`
	// This member contains information about the desired properties of the credential to be created. The sequence
	// is ordered from most preferred to least preferred. The client makes a best-effort to create the most
	// preferred credential that it can.
	PubKeyCredParams []PublicKeyCredentialParameters `json:"pubKeyCredParams"`
	// This member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
	// This is treated as a hint, and MAY be overridden by the client.
	Timeout time.Duration `json:"timeout,omitempty"`
	// This member is intended for use by Relying Parties that wish to limit the creation of multiple credentials
	// for the same account on a single authenticator. The client is requested to return an error if the new
	// credential would be created on an authenticator that also contains one of the credentials enumerated in this
	// parameter.
	ExcludeCredentials []PublicKeyCredentialDescriptor `json:"excludeCredentials,omitempty"`
	// This member is intended for use by Relying Parties that wish to select the appropriate authenticators to
	// participate in the create() operation.
	AuthenticatorSelection AuthenticatorSelectionCriteria `json:"authenticatorSelection"`
	// This member is intended for use by Relying Parties that wish to express their preference for attestation
	// conveyance. Its values SHOULD be members of AttestationConveyancePreference. Client platforms MUST ignore
	// unknown values, treating an unknown value as if the member does not exist. Its default value is "none".
	Attestation string `json:"attestation"`
	// This member contains additional parameters requesting additional processing by the client and authenticator.
	// For example, the caller may request that only authenticators with certain capabilities be used to create the
	// credential, or that particular information be returned in the attestation object.
	Extensions map[string]interface{} `json:"extensions"`
}

// AllowsAlgorithm returns true if the creation options allow the given algorithm.
func (creationOptions *PublicKeyCredentialCreationOptions) AllowsAlgorithm(algorithm cose.Algorithm) bool {
	for _, param := range creationOptions.PubKeyCredParams {
		if param.COSEAlgorithmIdentifier == algorithm {
			return true
		}
	}
	return false
}

// PublicKeyCreationCredential contains the attributes when a new credential is created.
type PublicKeyCreationCredential struct {
	// ID is the base64url encoding of the RawID.
	ID string `json:"id"`
	// Type is "public-key".
	Type string `json:"type"`
	// RawID is the credential ID, chosen by the authenticator. The credential ID is used to look up credentials for
	// use, and is therefore expected to be globally unique with high probability across all credentials of the same
	// type, across all authenticators.
	RawID []byte `json:"rawId"`
	// Response contains the authenticator's response to the client's request to create a public key credential.
	Response AuthenticatorAttestationResponse `json:"response"`
	// ClientExtensionResults is a map containing extension identifier → client extension output entries produced by
	// the extension’s client extension processing.
	ClientExtensionResults map[string]interface{} `json:"clientExtensionResults"`
}

// VerifyCreationCredential verifies that a creation credential is valid for the given options by
// performing steps 4-21 of https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential.
func VerifyCreationCredential(
	creationOptions *PublicKeyCredentialCreationOptions,
	credential *PublicKeyCreationCredential,
	verifyOptions ...VerifyOption,
) error {
	cfg, err := getVerifyConfig(verifyOptions...)
	if err != nil {
		return err
	}

	//  4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults().
	//  5. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
	//  6. Let C, the client data claimed as collected during the credential creation, be the result of running an
	//     implementation-specific JSON parser on JSONtext.
	clientData, err := credential.Response.UnmarshalClientData()
	if err != nil {
		return fmt.Errorf("invalid client data: %w", err)
	}

	//  7. Verify that the value of C.type is webauthn.create.
	if clientData.Type != "webauthn.create" {
		return fmt.Errorf("invalid client data type")
	}

	//  8. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
	expectedChallenge := base64.RawURLEncoding.EncodeToString(creationOptions.Challenge)
	if !stringsAreEqual(expectedChallenge, clientData.Challenge) {
		return fmt.Errorf("invalid client data challenge")
	}

	//  9. Verify that the value of C.origin matches the Relying Party's origin.
	if !stringsAreEqual(creationOptions.RP.ID, clientData.Origin) {
		return fmt.Errorf("invalid client data origin")
	}

	// 10. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection
	//     over which the assertion was obtained. If Token Binding was used on that TLS connection, also verify that
	//     C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
	//     - not implemented

	// 11. Let hash be the result of computing a hash over response.clientDataJSON using SHA-256.
	clientDataJSONHash := credential.Response.GetClientDataJSONHash()

	// 12. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to
	//     obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement
	//     attStmt.
	attestationObject, err := credential.Response.UnmarshalAttestationObject()
	if err != nil {
		return fmt.Errorf("invalid attestation object: %w", err)
	}

	authenticatorData, err := attestationObject.UnmarshalAuthenticatorData()
	if err != nil {
		return fmt.Errorf("invalid authenticator data: %w", err)
	}

	// 13. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
	expectedRPIDHash := sha256.Sum256([]byte(creationOptions.RP.ID))
	if !bytesAreEqual(expectedRPIDHash[:], authenticatorData.RPIDHash[:]) {
		return fmt.Errorf("invalid RP ID Hash")
	}

	// 14. Verify that the User Present bit of the flags in authData is set.
	if !authenticatorData.Flags.UserPresent() {
		return fmt.Errorf("user not present in authenticator data")
	}

	// 15. If user verification is required for this registration, verify that the User Verified bit of the flags in
	//     authData is set.
	if creationOptions.AuthenticatorSelection.UserVerification == UserVerificationRequired &&
		!authenticatorData.Flags.UserVerified() {
		return fmt.Errorf("user not verified in authenticator data")
	}

	// 16. Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of one of
	//     the items in options.pubKeyCredParams.
	key, _, err := cose.UnmarshalPublicKey(authenticatorData.AttestedCredentialData.CredentialPublicKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	if !creationOptions.AllowsAlgorithm(key.Algorithm()) {
		return fmt.Errorf("invalid algorithm")
	}

	// 17. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator
	//     extension outputs in the extensions in authData are as expected, considering the client extension input
	//     values that were given in options.extensions and any specific policy of the Relying Party regarding
	//     unsolicited extensions, i.e., those that were not specified as part of options.extensions. In the general
	//     case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
	//     - not implemented

	// 18. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the
	//     set of supported WebAuthn Attestation Statement Format Identifier values. An up-to-date list of registered
	//     WebAuthn Attestation Statement Format Identifier values is maintained in the IANA "WebAuthn Attestation
	//     Statement Format Identifiers" registry [IANA-WebAuthn-Registries] established by [RFC8809].
	// 19. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using
	//     the attestation statement format fmt’s verification procedure given attStmt, authData and hash.
	result, err := VerifyAttestationStatement(attestationObject, clientDataJSONHash)
	if err != nil {
		return fmt.Errorf("invalid attestation statement format: %w", err)
	}

	// 20. If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root certificates)
	//     for that attestation type and attestation statement format fmt, from a trusted source or from policy. For
	//     example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using
	//     the aaguid in the attestedCredentialData in authData.
	// 21. Assess the attestation trustworthiness using the outputs of the verification procedure in step 19, as
	//     follows:
	//     - If no attestation was provided, verify that None attestation is acceptable under Relying Party policy.
	//     - If self attestation was used, verify that self attestation is acceptable under Relying Party policy.
	//     - Otherwise, use the X.509 certificates returned as the attestation trust path from the verification
	//       procedure to verify that the attestation public key either correctly chains up to an acceptable root
	//       certificate, or is itself an acceptable certificate (i.e., it and the root certificate obtained in Step
	//       20 may be the same).

	if _, allowed := cfg.allowedTypes[result.Type]; !allowed {
		return fmt.Errorf("type not allowed: %s", result.Type)
	}
	if _, allowed := cfg.allowedFormats[attestationObject.Format]; !allowed {
		return fmt.Errorf("format not allowed: %s", attestationObject.Format)
	}

	switch attestationObject.Format {
	case AttestationFormatApple:
	case AttestationFormatAndroidSafetyNet:
	case AttestationFormatFIDOU2F:
		// Theoretically we should be able to verify the device using the FIDO Metadata service. However, in reality the
		// service is neither complete nor does it provide accurate information, so for now we will always trust
		// FIDO-U2F keys.
	default:
	}

	return nil
}
