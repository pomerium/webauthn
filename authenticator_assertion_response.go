package webauthn

import (
	"crypto/sha256"
	"encoding/base64"
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

// MarshalJSON marshals the AuthenticatorAssertionResponse as JSON.
func (response AuthenticatorAssertionResponse) MarshalJSON() ([]byte, error) {
	type Override AuthenticatorAssertionResponse
	return json.Marshal(struct {
		Override
		ClientDataJSON    string  `json:"clientDataJSON"`
		AuthenticatorData string  `json:"authenticatorData"`
		Signature         string  `json:"signature"`
		UserHandle        *string `json:"userHandle"`
	}{
		Override:          Override(response),
		ClientDataJSON:    toBase64URL(response.ClientDataJSON),
		AuthenticatorData: toBase64URL(response.AuthenticatorData),
		Signature:         toBase64URL(response.Signature),
		UserHandle:        toNullableBase64URL(response.UserHandle),
	})
}

// UnmarshalJSON unmarshals the AuthenticatorAssertionResponse from JSON.
func (response *AuthenticatorAssertionResponse) UnmarshalJSON(raw []byte) error {
	type Override AuthenticatorAssertionResponse
	var override struct {
		Override
		ClientDataJSON    string `json:"clientDataJSON"`
		AuthenticatorData string `json:"authenticatorData"`
		Signature         string `json:"signature"`
		UserHandle        string `json:"userHandle"`
	}
	err := json.Unmarshal(raw, &override)
	if err != nil {
		return err
	}

	*response = AuthenticatorAssertionResponse(override.Override)
	response.ClientDataJSON, err = base64.RawURLEncoding.DecodeString(override.ClientDataJSON)
	if err != nil {
		return err
	}
	response.AuthenticatorData, err = base64.RawURLEncoding.DecodeString(override.AuthenticatorData)
	if err != nil {
		return err
	}
	response.Signature, err = base64.RawURLEncoding.DecodeString(override.Signature)
	if err != nil {
		return err
	}
	response.UserHandle, err = base64.RawURLEncoding.DecodeString(override.UserHandle)
	if err != nil {
		return err
	}
	return nil
}
