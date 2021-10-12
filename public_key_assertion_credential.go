package webauthn

import "time"

// The PublicKeyCredentialRequestOptions supplies get() with the data it needs to generate an assertion.
// Its challenge member MUST be present, while its other members are OPTIONAL.
type PublicKeyCredentialRequestOptions struct {
	// This member represents a challenge that the selected authenticator signs, along with other data, when
	// producing an authentication assertion.
	Challenge []byte `json:"challenge"`
	// This OPTIONAL member specifies a time, in milliseconds, that the caller is willing to wait for the call to
	// complete. The value is treated as a hint, and MAY be overridden by the client.
	Timeout time.Duration `json:"timeout,omitempty"`
	// This OPTIONAL member specifies the relying party identifier claimed by the caller. If omitted, its
	// value will be the CredentialsContainer object’s relevant settings object's origin's effective domain.
	RPID string `json:"rpId,omitempty"`
	// This OPTIONAL member contains a list of PublicKeyCredentialDescriptor objects representing public key
	// credentials acceptable to the caller, in descending order of the caller’s preference (the first item in the
	// list is the most preferred credential, and so on down the list).
	AllowCredentials []PublicKeyCredentialDescriptor `json:"allowCredentials,omitempty"`
	// This OPTIONAL member describes the Relying Party's requirements regarding user verification for the get()
	// operation. The value SHOULD be a member of UserVerificationRequirement but client platforms MUST ignore
	// unknown values, treating an unknown value as if the member does not exist. Eligible authenticators are
	// filtered to only those capable of satisfying this requirement.
	UserVerification string `json:"userVerification,omitempty"`
	// This OPTIONAL member contains additional parameters requesting additional processing by the client and
	// authenticator. For example, if transaction confirmation is sought from the user, then the prompt string
	// might be included as an extension.
	Extensions map[string]interface{} `json:"extensions,omitempty"`
}

// PublicKeyAssertionCredential contains the attributes when a new assertion is requested.
type PublicKeyAssertionCredential struct {
	// ID is the base64url encoding of the RawID.
	ID string `json:"id"`
	// Type is "public-key".
	Type string `json:"type"`
	// RawID is the credential ID, chosen by the authenticator. The credential ID is used to look up credentials for
	// use, and is therefore expected to be globally unique with high probability across all credentials of the same
	// type, across all authenticators.
	RawID []byte `json:"rawId"`
	// Response contains the authenticator's response to the client's request to generate an authentication
	// assertion.
	Response AuthenticatorAssertionResponse `json:"response"`
	// ClientExtensionResults is a map containing extension identifier → client extension output entries produced by
	// the extension’s client extension processing.
	ClientExtensionResults map[string]interface{} `json:"clientExtensionResults"`
}

// VerifyAssertionCredential verifies that an assertion credential is valid for the given options by
// performing steps 4-21 of https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion.
func VerifyAssertionCredential(
	requestOptions *PublicKeyCredentialRequestOptions,
	credential *PublicKeyAssertionCredential,
	verifyOptions ...VerifyOption,
) error {
	//  4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults().
	//  5. If options.allowCredentials is not empty, verify that credential.id identifies one of the public key
	//     credentials listed in options.allowCredentials.
	//  6. Identify the user being authenticated and verify that this user is the owner of the public key credential
	//     source credentialSource identified by credential.id:
	//     - If the user was identified before the authentication ceremony was initiated, e.g., via a username or
	//       cookie, verify that the identified user is the owner of credentialSource. If response.userHandle is
	//       present, let userHandle be its value. Verify that userHandle also maps to the same user.
	//     - If the user was not identified before the authentication ceremony was initiated, verify that
	//       response.userHandle is present, and that the user identified by this value is the owner of
	//       credentialSource.
	//  7. Using credential.id (or credential.rawId, if base64url encoding is inappropriate for your use case), look up
	//     the corresponding credential public key and let credentialPublicKey be that credential public key.
	//  8. Let cData, authData and sig denote the value of response’s clientDataJSON, authenticatorData, and signature
	//     respectively.
	//  9. Let JSONtext be the result of running UTF-8 decode on the value of cData.
	// 10. Let C, the client data claimed as used for the signature, be the result of running an
	//     implementation-specific JSON parser on JSONtext.
	// 11. Verify that the value of C.type is the string webauthn.get.
	// 12. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
	// 13. Verify that the value of C.origin matches the Relying Party's origin.
	// 14. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection
	//     over which the attestation was obtained. If Token Binding was used on that TLS connection, also verify that
	//     C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
	// 15. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
	// 16. Verify that the User Present bit of the flags in authData is set.
	// 17. If user verification is required for this assertion, verify that the User Verified bit of the flags in
	//     authData is set.
	// 18. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator
	//     extension outputs in the extensions in authData are as expected, considering the client extension input
	//     values that were given in options.extensions and any specific policy of the Relying Party regarding
	//     unsolicited extensions, i.e., those that were not specified as part of options.extensions. In the general
	//     case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
	// 19. Let hash be the result of computing a hash over the cData using SHA-256.
	// 20. Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData
	//     and hash.
	// 21. Let storedSignCount be the stored signature counter value associated with credential.id. If
	//     authData.signCount is nonzero or storedSignCount is nonzero, then run the following sub-step:
	//     - If authData.signCount is
	//       - greater than storedSignCount:
	//         Update storedSignCount to be the value of authData.signCount.
	//       - less than or equal to storedSignCount:
	//         This is a signal that the authenticator may be cloned, i.e. at least two copies of the credential
	//         private key may exist and are being used in parallel. Relying Parties should incorporate this
	//         information into their risk scoring. Whether the Relying Party updates storedSignCount in this case, or
	//         not, or fails the authentication ceremony or not, is Relying Party-specific.
	//     - not implemented

	return nil
}
