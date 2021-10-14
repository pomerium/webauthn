package webauthn

import (
	"crypto/sha256"
	"encoding/json"
)

// The AuthenticatorAttestationResponse interface represents the authenticator's response to a client's request for
// the creation of a new public key credential. It contains information about the new credential that can be used to
// identify it for later use, and metadata that can be used by the WebAuthn Relying Party to assess the
// characteristics of the credential during registration.
type AuthenticatorAttestationResponse struct {
	// ClientDataJSON contains the JSON-compatible serialization of client data passed to the authenticator by the
	// client in order to generate this credential. The exact JSON serialization MUST be preserved, as the hash of
	// the serialized client data has been computed over it.
	ClientDataJSON []byte `json:"clientDataJSON"`
	// AttestationObject contains an attestation object, which is opaque to, and cryptographically protected
	// against tampering by, the client. The attestation object contains both authenticator data and an attestation
	// statement. The former contains the AAGUID, a unique credential ID, and the credential public key. The
	// contents of the attestation statement are determined by the attestation statement format used by the
	// authenticator. It also contains any additional information that the Relying Party's server requires to
	// validate the attestation statement, as well as to decode and validate the authenticator data along with the
	// JSON-compatible serialization of client data.
	AttestationObject []byte `json:"attestationObject"`
}

// GetClientDataJSONHash returns the SHA-256 hash of the clientDataJSON data.
func (response *AuthenticatorAttestationResponse) GetClientDataJSONHash() ClientDataJSONHash {
	return sha256.Sum256(response.ClientDataJSON)
}

// UnmarshalAttestationObject unmarshals the attestation object.
func (response *AuthenticatorAttestationResponse) UnmarshalAttestationObject() (*AttestationObject, error) {
	obj, _, err := UnmarshalAttestationObject(response.AttestationObject)
	return obj, err
}

// UnmarshalClientData unmarshals the client data.
func (response *AuthenticatorAttestationResponse) UnmarshalClientData() (*CollectedClientData, error) {
	var data CollectedClientData
	err := json.Unmarshal(response.ClientDataJSON, &data)
	if err != nil {
		return nil, err
	}
	return &data, nil
}

// MarshalJSON marshals the AuthenticatorAttestationResponse as JSON.
func (response AuthenticatorAttestationResponse) MarshalJSON() ([]byte, error) {
	type Override AuthenticatorAttestationResponse
	return json.Marshal(struct {
		Override
		ClientDataJSON    string `json:"clientDataJSON"`
		AttestationObject string `json:"attestationObject"`
	}{
		Override:          Override(response),
		ClientDataJSON:    toBase64URL(response.ClientDataJSON),
		AttestationObject: toBase64URL(response.AttestationObject),
	})
}

// UnmarshalJSON unmarshals the AuthenticatorAttestationResponse as JSON.
func (response *AuthenticatorAttestationResponse) UnmarshalJSON(raw []byte) error {
	type Override AuthenticatorAttestationResponse
	var override struct {
		Override
		ClientDataJSON    string `json:"clientDataJSON"`
		AttestationObject string `json:"attestationObject"`
	}
	err := json.Unmarshal(raw, &override)
	if err != nil {
		return err
	}

	*response = AuthenticatorAttestationResponse(override.Override)
	response.ClientDataJSON, err = fromBase64URL(override.ClientDataJSON)
	if err != nil {
		return err
	}
	response.AttestationObject, err = fromBase64URL(override.AttestationObject)
	if err != nil {
		return err
	}
	return nil
}
