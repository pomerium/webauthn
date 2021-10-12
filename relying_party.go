package webauthn

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/pomerium/webauthn/cose"
)

// ErrCredentialNotFound is the error used to indicate a credential wasn't found.
var ErrCredentialNotFound = errors.New("credential not found")

// A Credential is the public key and user id stored by the relying party to identify
// a private key bound to an authenticator.
type Credential struct {
	ID        []byte `json:"id"`
	OwnerID   []byte `json:"ownerId"`
	PublicKey []byte `json:"publicKey"`
}

// CredentialStorage retrieves and saves credentials.
type CredentialStorage interface {
	// GetCredential retrieves a credential from storage. If no credential is found for the
	// given ID return ErrCredentialNotFound.
	GetCredential(credentialID []byte) (*Credential, error)
	// SetCredential saves a credential to storage.
	SetCredential(credential *Credential) error
}

// A RelyingParty is the entity that utilizes the Web Authentication API to register and
// authenticate users.
type RelyingParty struct {
	credentialStorage CredentialStorage
	id                []byte
	origin            string
}

// VerifyAuthenticationCeremony verifies an authentication ceremony by performing steps
// 4-22 of https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion.
func (rp *RelyingParty) VerifyAuthenticationCeremony(
	options *PublicKeyCredentialRequestOptions,
	credential *PublicKeyAssertionCredential,
) (*Credential, error) {
	//  4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults().

	//  5. If options.allowCredentials is not empty, verify that credential.id identifies one of the public key
	//     credentials listed in options.allowCredentials.
	if len(options.AllowCredentials) > 0 {
		found := false
		for _, allowCredential := range options.AllowCredentials {
			found = found || bytesAreEqual(allowCredential.ID, credential.RawID)
		}
		if !found {
			return nil, fmt.Errorf("supplied credential is not one of the allowed credentials")
		}
	}

	//  6. Identify the user being authenticated and verify that this user is the owner of the public key credential
	//     source credentialSource identified by credential.id:
	//     - If the user was identified before the authentication ceremony was initiated, e.g., via a username or
	//       cookie, verify that the identified user is the owner of credentialSource. If response.userHandle is
	//       present, let userHandle be its value. Verify that userHandle also maps to the same user.
	//     - If the user was not identified before the authentication ceremony was initiated, verify that
	//       response.userHandle is present, and that the user identified by this value is the owner of
	//       credentialSource.
	serverCredential, err := rp.credentialStorage.GetCredential(credential.RawID)
	if err != nil {
		return nil, err
	} else if !bytesAreEqual(credential.Response.UserHandle, serverCredential.OwnerID) {
		return nil, fmt.Errorf("invalid user handle for credential")
	}

	//  7. Using credential.id (or credential.rawId, if base64url encoding is inappropriate for your use case), look up
	//     the corresponding credential public key and let credentialPublicKey be that credential public key.
	credentialPublicKey := serverCredential.PublicKey

	//  8. Let cData, authData and sig denote the value of response’s clientDataJSON, authenticatorData, and signature
	//     respectively.
	//  9. Let JSONtext be the result of running UTF-8 decode on the value of cData.
	// 10. Let C, the client data claimed as used for the signature, be the result of running an
	//     implementation-specific JSON parser on JSONtext.
	clientData, err := credential.Response.UnmarshalClientData()
	if err != nil {
		return nil, fmt.Errorf("invalid client data: %w", err)
	}

	// 11. Verify that the value of C.type is the string webauthn.get.
	if clientData.Type != "webauthn.get" {
		return nil, fmt.Errorf("invalid client data type")
	}

	// 12. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
	if !stringsAreEqual(clientData.Challenge, base64.RawURLEncoding.EncodeToString(options.Challenge)) {
		return nil, fmt.Errorf("invalid client data challenge")
	}

	// 13. Verify that the value of C.origin matches the Relying Party's origin.
	if !stringsAreEqual(clientData.Origin, rp.origin) {
		return nil, fmt.Errorf("invalid client data origin")
	}

	// 14. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection
	//     over which the attestation was obtained. If Token Binding was used on that TLS connection, also verify that
	//     C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
	// - not implemented

	// 15. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
	authenticatorData, err := credential.Response.UnmarshalAuthenticatorData()
	if err != nil {
		return nil, fmt.Errorf("invalid authenticator data: %w", err)
	}

	expectedRPIDHash := sha256.Sum256(rp.id)
	if !bytesAreEqual(authenticatorData.RPIDHash[:], expectedRPIDHash[:]) {
		return nil, fmt.Errorf("invalid rp id hash")
	}

	// 16. Verify that the User Present bit of the flags in authData is set.
	if !authenticatorData.Flags.UserPresent() {
		return nil, fmt.Errorf("user not present")
	}

	// 17. If user verification is required for this assertion, verify that the User Verified bit of the flags in
	//     authData is set.
	if options.UserVerification == UserVerificationRequired && !authenticatorData.Flags.UserVerified() {
		return nil, fmt.Errorf("user not verified")
	}

	// 18. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator
	//     extension outputs in the extensions in authData are as expected, considering the client extension input
	//     values that were given in options.extensions and any specific policy of the Relying Party regarding
	//     unsolicited extensions, i.e., those that were not specified as part of options.extensions. In the general
	//     case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
	// - not implemented

	// 19. Let hash be the result of computing a hash over the cData using SHA-256.
	clientDataJSONHash := credential.Response.GetClientDataJSONHash()

	// 20. Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData
	//     and hash.
	verificationData := concat(credential.Response.AuthenticatorData, clientDataJSONHash[:])
	publicKey, _, err := cose.UnmarshalPublicKey(credentialPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	err = publicKey.Verify(verificationData, credential.Response.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}

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
	// - not implemented

	// 22. If all the above steps are successful, continue with the authentication ceremony as appropriate. Otherwise,
	//     fail the authentication ceremony.
	return serverCredential, nil
}

// VerifyRegistrationCeremony verifies a registration ceremony by performing steps
// 4-24 of https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential.
func (rp *RelyingParty) VerifyRegistrationCeremony(
	options *PublicKeyCredentialCreationOptions,
	credential *PublicKeyCreationCredential,
) (*Credential, error) {
	panic("not implemented")
}
