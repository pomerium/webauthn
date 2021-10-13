package webauthn

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"

	"github.com/pomerium/webauthn/cose"
)

var (

	// ErrCredentialNotFound is the error used to indicate a credential wasn't found.
	ErrCredentialNotFound = errors.New("credential not found")
	// ErrCredentialRegisteredToDifferentUser is the error used to indicate a credential is being used by another user.
	ErrCredentialRegisteredToDifferentUser = errors.New("credential registered to another user")
)

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
	GetCredential(ctx context.Context, credentialID []byte) (*Credential, error)
	// SetCredential saves a credential to storage.
	SetCredential(ctx context.Context, credential *Credential) error
}

// An InMemoryCredentialStorage stores credential in an in-memory map.
type InMemoryCredentialStorage struct {
	m map[string]*Credential
}

// NewInMemoryCredentialStorage creates a new InMemoryCredentialStorage.
func NewInMemoryCredentialStorage() *InMemoryCredentialStorage {
	return &InMemoryCredentialStorage{
		m: make(map[string]*Credential),
	}
}

// GetCredential gets the credential from the map.
func (storage *InMemoryCredentialStorage) GetCredential(ctx context.Context, credentialID []byte) (*Credential, error) {
	credential, ok := storage.m[string(credentialID)]
	if !ok {
		return nil, ErrCredentialNotFound
	}
	return credential, nil
}

// SetCredential sets the credential in the map.
func (storage *InMemoryCredentialStorage) SetCredential(ctx context.Context, credential *Credential) error {
	storage.m[string(credential.ID)] = credential
	return nil
}

// A RelyingParty is the entity that utilizes the Web Authentication API to register and
// authenticate users.
type RelyingParty struct {
	origin            string
	id                []byte
	credentialStorage CredentialStorage
}

// NewRelyingParty creates a new RelyingParty.
func NewRelyingParty(originURL string, credentialStorage CredentialStorage) *RelyingParty {
	rp := &RelyingParty{
		origin:            originURL,
		credentialStorage: credentialStorage,
	}
	if u, err := url.Parse(originURL); err == nil {
		rp.id = []byte(u.Hostname())
	} else {
		rp.id = []byte(originURL)
	}
	return rp
}

// VerifyAuthenticationCeremony verifies an authentication ceremony by performing steps
// 4-22 of https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion.
func (rp *RelyingParty) VerifyAuthenticationCeremony(
	ctx context.Context,
	options *PublicKeyCredentialRequestOptions,
	credential *PublicKeyAssertionCredential,
	verifyOptions ...VerifyOption,
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
	serverCredential, err := rp.credentialStorage.GetCredential(ctx, credential.RawID)
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
	if clientData.Type != ClientDataTypeGet {
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
	ctx context.Context,
	creationOptions *PublicKeyCredentialCreationOptions,
	credential *PublicKeyCreationCredential,
	verifyOptions ...VerifyOption,
) (*Credential, error) {
	cfg, err := getVerifyConfig(verifyOptions...)
	if err != nil {
		return nil, err
	}

	//  4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults().
	//  5. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
	//  6. Let C, the client data claimed as collected during the credential creation, be the result of running an
	//     implementation-specific JSON parser on JSONtext.
	clientData, err := credential.Response.UnmarshalClientData()
	if err != nil {
		return nil, fmt.Errorf("invalid client data: %w", err)
	}

	//  7. Verify that the value of C.type is webauthn.create.
	if clientData.Type != ClientDataTypeCreate {
		return nil, fmt.Errorf("invalid client data type")
	}

	//  8. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
	expectedChallenge := base64.RawURLEncoding.EncodeToString(creationOptions.Challenge)
	if !stringsAreEqual(expectedChallenge, clientData.Challenge) {
		return nil, fmt.Errorf("invalid client data challenge")
	}

	//  9. Verify that the value of C.origin matches the Relying Party's origin.
	if !stringsAreEqual(rp.origin, clientData.Origin) {
		return nil, fmt.Errorf("invalid client data origin")
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
		return nil, fmt.Errorf("invalid attestation object: %w", err)
	}

	authenticatorData, err := attestationObject.UnmarshalAuthenticatorData()
	if err != nil {
		return nil, fmt.Errorf("invalid authenticator data: %w", err)
	}

	// 13. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
	expectedRPIDHash := sha256.Sum256(rp.id)
	if !bytesAreEqual(expectedRPIDHash[:], authenticatorData.RPIDHash[:]) {
		return nil, fmt.Errorf("invalid RP ID Hash")
	}

	// 14. Verify that the User Present bit of the flags in authData is set.
	if !authenticatorData.Flags.UserPresent() {
		return nil, fmt.Errorf("user not present in authenticator data")
	}

	// 15. If user verification is required for this registration, verify that the User Verified bit of the flags in
	//     authData is set.
	if creationOptions.AuthenticatorSelection.UserVerification == UserVerificationRequired &&
		!authenticatorData.Flags.UserVerified() {
		return nil, fmt.Errorf("user not verified in authenticator data")
	}

	// 16. Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of one of
	//     the items in options.pubKeyCredParams.
	key, _, err := cose.UnmarshalPublicKey(authenticatorData.AttestedCredentialData.CredentialPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	if !creationOptions.AllowsAlgorithm(key.Algorithm()) {
		return nil, fmt.Errorf("invalid algorithm")
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
		return nil, fmt.Errorf("invalid attestation statement format: %w", err)
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
		return nil, fmt.Errorf("type not allowed: %s", result.Type)
	}
	if _, allowed := cfg.allowedFormats[attestationObject.Format]; !allowed {
		return nil, fmt.Errorf("format not allowed: %s", attestationObject.Format)
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

	// 22. Check that the credentialId is not yet registered to any other user. If registration is requested for a
	//     credential that is already registered to a different user, the Relying Party SHOULD fail this registration
	//     ceremony, or it MAY decide to accept the registration, e.g. while deleting the older registration.
	existingCredential, err := rp.credentialStorage.GetCredential(ctx, credential.RawID)
	switch {
	case errors.Is(err, ErrCredentialNotFound):
	case err != nil:
		return nil, fmt.Errorf("error retrieving credential: %w", err)
	case !bytesAreEqual(existingCredential.OwnerID, creationOptions.User.ID):
		return nil, ErrCredentialRegisteredToDifferentUser
	}

	// 23. If the attestation statement attStmt verified successfully and is found to be trustworthy, then register the
	//     new credential with the account that was denoted in options.user:
	//     - Associate the user’s account with the credentialId and credentialPublicKey in
	//       authData.attestedCredentialData, as appropriate for the Relying Party's system.
	//     - Associate the credentialId with a new stored signature counter value initialized to the value of
	//       authData.signCount.
	serverCredential := &Credential{
		ID:        credential.RawID,
		OwnerID:   creationOptions.User.ID,
		PublicKey: authenticatorData.AttestedCredentialData.CredentialPublicKey,
	}
	err = rp.credentialStorage.SetCredential(ctx, serverCredential)
	if err != nil {
		return nil, fmt.Errorf("error saving credential: %w", err)
	}

	//     It is RECOMMENDED to also:
	//     - Associate the credentialId with the transport hints returned by calling
	//       credential.response.getTransports(). This value SHOULD NOT be modified before or after storing it. It is
	//       RECOMMENDED to use this value to populate the transports of the allowCredentials option in future get()
	//       calls to help the client know how to find a suitable authenticator.
	//       - not implemented
	//     - If the attestation statement attStmt successfully verified but is not trustworthy per step 21 above, the
	//       Relying Party SHOULD fail the registration ceremony.
	//       - implemented in step 21

	return serverCredential, nil
}
