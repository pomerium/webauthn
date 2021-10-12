package webauthn

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/pomerium/webauthn/cose"
)

// AuthenticatorSelectionCriteria specifies requirements regarding authenticator attributes.
type AuthenticatorSelectionCriteria struct {
	// AuthenticatorAttachment, if present, filters eligible authenticators. The value SHOULD be a member of
	// AuthenticatorAttachment but client platforms MUST ignore unknown values, treating an unknown value as if the
	// member does not exist.
	AuthenticatorAttachment string `json:"authenticatorAttachment"`
	// ResidentKey specifies the extent to which the Relying Party desires to create a client-side discoverable
	// credential. For historical reasons the naming retains the deprecated “resident” terminology. The value
	// SHOULD be a member of ResidentKeyRequirement but client platforms MUST ignore unknown values, treating an
	// unknown value as if the member does not exist. If no value is given then the effective value is required if
	// requireResidentKey is true or discouraged if it is false or absent.
	ResidentKey string `json:"residentKey"`
	// RequireResidentKey is retained for backwards compatibility with WebAuthn Level 1 and, for historical reasons,
	// its naming retains the deprecated “resident” terminology for discoverable credentials. Relying Parties SHOULD
	// set it to true if, and only if, residentKey is set to required.
	RequireResidentKey bool `json:"requireResidentKey"`
	// UserVerification describes the Relying Party's requirements regarding user verification for the create()
	// operation. Eligible authenticators are filtered to only those capable of satisfying this requirement. The
	// value SHOULD be a member of UserVerificationRequirement but client platforms MUST ignore unknown values,
	// treating an unknown value as if the member does not exist.
	UserVerification string `json:"userVerification"`
}

// A Base64RawURLBytes is a slice of bytes. The JSON format of these bytes will be base64-raw-url encoded.
type Base64RawURLBytes []byte

// MarshalJSON marshals the Base64RawURLBytes as JSON.
func (bs Base64RawURLBytes) MarshalJSON() ([]byte, error) {
	str := base64.RawURLEncoding.EncodeToString(bs)
	return json.Marshal(str)
}

// UnmarshalJSON unmarshals the Base64RawURLBytes from JSON.
func (bs *Base64RawURLBytes) UnmarshalJSON(raw []byte) error {
	var str string
	err := json.Unmarshal(raw, &str)
	if err != nil {
		return err
	}

	*bs, err = base64.RawURLEncoding.DecodeString(str)
	return err
}

// CollectedClientData represents the contextual bindings of both the WebAuthn Relying Party and the client.
type CollectedClientData struct {
	// Type contains the string "webauthn.create" when creating new credentials, and "webauthn.get" when
	// getting an assertion from an existing credential. The purpose of this member is to prevent certain types of
	// signature confusion attacks (where an attacker substitutes one legitimate signature for another).
	Type string `json:"type"`
	// Challenge contains the base64url encoding of the challenge provided by the Relying Party.
	Challenge string `json:"challenge"`
	// Origin contains the fully qualified origin of the requester, as provided to the authenticator by the
	// client.
	Origin string `json:"origin"`
	// CrossOrigin contains the inverse of the sameOriginWithAncestors argument value that was passed into the
	// internal method.
	CrossOrigin bool `json:"crossOrigin"`
	// TokenBinding contains information about the state of the Token Binding protocol used when communicating with
	// the Relying Party. Its absence indicates that the client doesn’t support token binding.
	TokenBinding *TokenBinding `json:"tokenBinding"`
}

// ClientDataJSONHash represents the SHA-256 hash of the clientDataJSON data.
type ClientDataJSONHash = [sha256.Size]byte

// PublicKeyAssertionCredential contains the attributes when a new assertion is requested.
type PublicKeyAssertionCredential struct {
	// ID is the base64url encoding of the RawID.
	ID string `json:"id"`
	// Type is "public-key".
	Type string `json:"type"`
	// RawID is the credential ID, chosen by the authenticator. The credential ID is used to look up credentials for
	// use, and is therefore expected to be globally unique with high probability across all credentials of the same
	// type, across all authenticators.
	RawID Base64RawURLBytes `json:"rawId"`
	// Response contains the authenticator's response to the client's request to generate an authentication
	// assertion.
	Response AuthenticatorAssertionResponse `json:"response"`
	// ClientExtensionResults is a map containing extension identifier → client extension output entries produced by
	// the extension’s client extension processing.
	ClientExtensionResults map[string]interface{} `json:"clientExtensionResults"`
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
	RawID Base64RawURLBytes `json:"rawId"`
	// Response contains the authenticator's response to the client's request to create a public key credential.
	Response AuthenticatorAttestationResponse `json:"response"`
	// ClientExtensionResults is a map containing extension identifier → client extension output entries produced by
	// the extension’s client extension processing.
	ClientExtensionResults map[string]interface{} `json:"clientExtensionResults"`
}

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
	Challenge Base64RawURLBytes `json:"challenge"`
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

// The PublicKeyCredentialDescriptor contains the attributes that are specified by a caller when referring to a
// public key credential as an input parameter to the create() or get() methods.
type PublicKeyCredentialDescriptor struct {
	// This member contains the type of the public key credential the caller is referring to. The value SHOULD be a
	// member of PublicKeyCredentialType but client platforms MUST ignore any PublicKeyCredentialDescriptor with an
	// unknown type.
	Type string `json:"type"`
	// This member contains the credential ID of the public key credential the caller is referring to.
	ID Base64RawURLBytes `json:"id"`
	// This OPTIONAL member contains a hint as to how the client might communicate with the managing authenticator
	// of the public key credential the caller is referring to. The values SHOULD be members of
	// AuthenticatorTransport but client platforms MUST ignore unknown values.
	Transports []string `json:"transports"`
}

// PublicKeyCredentialParameters is used to supply additional parameters when creating a new credential.
type PublicKeyCredentialParameters struct {
	// This member specifies the type of credential to be created.
	Type string `json:"type"`
	// This member specifies the cryptographic signature algorithm with which the newly generated credential will
	// be used, and thus also the type of asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.
	COSEAlgorithmIdentifier cose.Algorithm `json:"alg"`
}

// The PublicKeyCredentialRequestOptions supplies get() with the data it needs to generate an assertion.
// Its challenge member MUST be present, while its other members are OPTIONAL.
type PublicKeyCredentialRequestOptions struct {
	// This member represents a challenge that the selected authenticator signs, along with other data, when
	// producing an authentication assertion.
	Challenge Base64RawURLBytes `json:"challenge"`
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

// The PublicKeyCredentialRpEntity is used to supply additional Relying Party attributes when creating a new
// credential.
type PublicKeyCredentialRpEntity struct {
	// A unique identifier for the Relying Party entity, which sets the RP ID.
	ID string `json:"id"`
	// A human-palatable identifier for the Relying Party, intended only for display.
	Name string `json:"name"`
}

// The PublicKeyCredentialUserEntity is used to supply additional user account attributes when creating a new
// credential.
type PublicKeyCredentialUserEntity struct {
	// The user handle of the user account entity. A user handle is an opaque byte sequence with a maximum size of
	// 64 bytes, and is not meant to be displayed to the user.
	//
	// To ensure secure operation, authentication and authorization decisions MUST be made on the basis of this id
	// member, not the displayName nor name members.
	//
	// The user handle MUST NOT contain personally identifying information about the user, such as a username or
	// e-mail address.
	ID Base64RawURLBytes `json:"id"`
	// A human-palatable name for the user account, intended only for display. For example, "Alex Müller" or
	// "田中倫". The Relying Party SHOULD let the user choose this, and SHOULD NOT restrict the choice more than
	// necessary.
	//
	// Authenticators MUST accept and store a 64-byte minimum length for a displayName member’s value.
	// Authenticators MAY truncate a displayName member’s value so that it fits within 64 bytes.
	DisplayName string `json:"displayName"`
	// A human-palatable identifier for a user account.
	Name string `json:"name"`
}

// A TokenBinding is established by a User Agent generating a private-public key pair (possibly within a secure
// hardware module, such as a Trusted Platform Module) per target server, providing the public key to the server,
// and proving possession of the corresponding private key.
type TokenBinding struct {
	// This member SHOULD be a member of TokenBindingStatus but client platforms MUST ignore unknown values,
	// treating an unknown value as if the tokenBinding member does not exist.
	Status string `json:"status"`
	// This member MUST be present if status is present, and MUST be a base64url encoding of the Token Binding ID
	// that was used when communicating with the Relying Party.
	ID string `json:"id"`
}

const (
	// AttestationConveyanceNone indicates that the Relying Party is not interested in authenticator attestation. For
	// example, in order to potentially avoid having to obtain user consent to relay identifying information to the
	// Relying Party, or to save a roundtrip to an Attestation CA or Anonymization CA. This is the default value.
	AttestationConveyanceNone = "none"
	// AttestationConveyanceIndirect indicates that the Relying Party prefers an attestation conveyance yielding
	// verifiable attestation statements, but allows the client to decide how to obtain such attestation statements.
	// The client MAY replace the authenticator-generated attestation statements with attestation statements generated
	// by an Anonymization CA, in order to protect the user’s privacy, or to assist Relying Parties with attestation
	// verification in a heterogeneous ecosystem.
	AttestationConveyanceIndirect = "indirect"
	// AttestationConveyanceDirect indicates that the Relying Party wants to receive the attestation statement as
	// generated by the authenticator.
	AttestationConveyanceDirect = "direct"
	// AttestationConveyanceEnterprise indicates that the Relying Party wants to receive an attestation statement that
	// may include uniquely identifying information. This is intended for controlled deployments within an enterprise
	// where the organization wishes to tie registrations to specific authenticators. User agents MUST NOT provide such
	// an attestation unless the user agent or authenticator configuration permits it for the requested RP ID.
	//
	// If permitted, the user agent SHOULD signal to the authenticator (at invocation time) that enterprise attestation
	// is requested, and convey the resulting AAGUID and attestation statement, unaltered, to the Relying Party.
	AttestationConveyanceEnterprise = "enterprise"
)

const (
	// AuthenticatorAttachmentPlatform indicates platform attachment.
	AuthenticatorAttachmentPlatform = "platform"
	// AuthenticatorAttachmentCrossPlatform indicates cross-platform attachment.
	AuthenticatorAttachmentCrossPlatform = "cross-platform"
)

const (
	// AuthenticatorTransportUSB indicates the respective authenticator can be contacted over removable USB.
	AuthenticatorTransportUSB = "usb"
	// AuthenticatorTransportNFC indicates the respective authenticator can be contacted over Near Field Communication
	// (NFC).
	AuthenticatorTransportNFC = "nfc"
	// AuthenticatorTransportBLE indicates the respective authenticator can be contacted over Bluetooth Smart
	// (Bluetooth Low Energy / BLE).
	AuthenticatorTransportBLE = "ble"
	// AuthenticatorTransportInternal indicates the respective authenticator is contacted using a client
	// device-specific transport, i.e., it is a platform authenticator. These authenticators are not removable from the
	// client device.
	AuthenticatorTransportInternal = "internal"
)

const (
	// ClientDataTypeCreate is used when creating new credentials.
	ClientDataTypeCreate = "webauthn.create"
	// ClientDataTypeGet is used when getting an assertion on an existing credential.
	ClientDataTypeGet = "webauthn.get"
)

const (
	// COSEAlgorithmIdentifierES256 is ECDSA w/ SHA-256.
	COSEAlgorithmIdentifierES256 = -7
	// COSEAlgorithmIdentifierRS256 is RSASSA-PKCS1-v1_5 using SHA-256.
	COSEAlgorithmIdentifierRS256 = -257
)

const (
	// PublicKeyCredentialTypePublicKey represents a public key credential.
	PublicKeyCredentialTypePublicKey = "public-key"
)

const (
	// ResidentKeyDiscouraged indicates the Relying Party prefers creating a server-side credential, but will accept a
	// client-side discoverable credential.
	ResidentKeyDiscouraged = "discouraged"
	// ResidentKeyPreferred indicates the Relying Party strongly prefers creating a client-side discoverable
	// credential, but will accept a server-side credential. For example, user agents SHOULD guide the user through
	// setting up user verification if needed to create a client-side discoverable credential in this case. This takes
	// precedence over the setting of userVerification.
	ResidentKeyPreferred = "preferred"
	// ResidentKeyRequired indicates the Relying Party requires a client-side discoverable credential, and is prepared
	// to receive an error if a client-side discoverable credential cannot be created.
	ResidentKeyRequired = "required"
)

const (
	// TokenBindingPresent indicates token binding was used when communicating with the Relying Party. In this case,
	// the id member MUST be present.
	TokenBindingPresent = "present"
	// TokenBindingSupported indicates the client supports token binding, but it was not negotiated when
	// communicating with the Relying Party.
	TokenBindingSupported = "supported"
)

const (
	// UserVerificationRequired indicates that the Relying Party requires user verification for the operation and will
	// fail the operation if the response does not have the UV flag set.
	UserVerificationRequired = "required"
	// UserVerificationPreferred indicates that the Relying Party prefers user verification for the operation if
	// possible, but will not fail the operation if the response does not have the UV flag set.
	UserVerificationPreferred = "preferred"
	// UserVerificationDiscouraged indicates that the Relying Party does not want user verification employed during the
	// operation (e.g., in the interest of minimizing disruption to the user interaction flow).
	UserVerificationDiscouraged = "discouraged"
)
