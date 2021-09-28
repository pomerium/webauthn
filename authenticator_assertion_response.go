package webauthn

import (
	"crypto/sha256"
	"encoding/json"
)

// The AuthenticatorAssertionResponse represents an authenticator's response to a client’s request for generation
// of a new authentication assertion given the WebAuthn Relying Party's challenge and OPTIONAL list of credentials
// it is aware of. This response contains a cryptographic signature proving possession of the credential private
// key, and optionally evidence of user consent to a specific transaction.
type AuthenticatorAssertionResponse struct {
	// ClientDataJSON contains the JSON-compatible serialization of client data passed to the authenticator by the
	// client in order to generate this assertion. The exact JSON serialization MUST be preserved, as the hash of
	// the serialized client data has been computed over it.
	ClientDataJSON []byte `json:"clientDataJSON"`
	// AuthenticatorData contains the authenticator data returned by the authenticator.
	AuthenticatorData []byte `json:"authenticatorData"`
	// Signature contains the raw signature returned from the authenticator.
	Signature []byte `json:"signature"`
	// UserHandle contains the user handle returned from the authenticator, or nil if the authenticator did not
	// return a user handle.
	UserHandle []byte `json:"userHandle"`
}

// GetClientDataJSONHash returns the SHA-256 hash of the clientDataJSON data.
func (response *AuthenticatorAssertionResponse) GetClientDataJSONHash() ClientDataJSONHash {
	return sha256.Sum256(response.ClientDataJSON)
}

// UnmarshalAuthenticatorData unmarshals the authenticator data.
func (response *AuthenticatorAssertionResponse) UnmarshalAuthenticatorData() (*AuthenticatorData, error) {
	data, _, err := UnmarshalAuthenticatorData(response.AuthenticatorData)
	return data, err
}

// UnmarshalClientData unmarshals the client data.
func (response *AuthenticatorAssertionResponse) UnmarshalClientData() (*CollectedClientData, error) {
	var data CollectedClientData
	err := json.Unmarshal(response.ClientDataJSON, &data)
	if err != nil {
		return nil, err
	}
	return &data, nil
}
