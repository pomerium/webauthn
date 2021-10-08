package webauthn

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
)

// Errors
var (
	ErrNoneNotAllowed              = fmt.Errorf("the None attestation type is not allowed")
	ErrSelfNotAllowed              = fmt.Errorf("the Self attestation type is not allowed")
	ErrInvalidAttestationTrustPath = fmt.Errorf("invalid attestation trust path")
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

// Verify verifies the AuthenticatorAttestationResponse.
func (response *AuthenticatorAttestationResponse) Verify(ctx context.Context, options ...VerifyOption) error {
	cfg, err := getVerifyConfig(options...)
	if err != nil {
		return err
	}

	attestationObject, err := response.UnmarshalAttestationObject()
	if err != nil {
		return err
	}

	authenticatorData, err := attestationObject.UnmarshalAuthenticatorData()
	if err != nil {
		return err
	}

	result, err := VerifyAttestationStatement(attestationObject, response.GetClientDataJSONHash())
	if err != nil {
		return err
	}

	// "None" has no trust path, so check if it's allowed in the policy.
	if result.Type == AttestationTypeNone {
		if cfg.allowNone {
			return nil
		}
		return ErrNoneNotAllowed
	}

	// "Self" has no trust path, so check if it's allowed in the policy.
	if result.Type == AttestationTypeSelf {
		if cfg.allowSelf {
			return nil
		}
		return ErrSelfNotAllowed
	}

	// All other formats need to be checked against trust anchors.
	trustAnchors, err := cfg.trustAnchorProvider.GetTrustAnchors(ctx,
		attestationObject.Format,
		result.Type,
		authenticatorData.AttestedCredentialData.AAGUID,
	)
	if err != nil {
		return err
	}

	for _, trustPath := range result.TrustPaths {
		if len(trustPath) == 0 {
			// ignore empty trust paths
			continue
		}

		// verify the cert is valid based on the trust anchors
		vo := x509.VerifyOptions{
			Roots: trustAnchors,
		}
		// if there's more than one certificate, add all the other certificates to
		// the intermediates
		if len(trustPath) > 1 {
			vo.Intermediates = x509.NewCertPool()
			for _, c := range trustPath[1:] {
				vo.Intermediates.AddCert(c)
			}
		}
		_, err := trustPath[0].Verify(vo)
		if err == nil {
			return nil
		}
	}

	return ErrInvalidAttestationTrustPath
}
