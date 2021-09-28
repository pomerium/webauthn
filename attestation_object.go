package webauthn

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// ErrInvalidAttestationObject indicates an invalid attestation object.
var ErrInvalidAttestationObject = errors.New("invalid attestation object")

// An AttestationObject conveys authenticator data and an attestation statement.
type AttestationObject struct {
	// The AuthData encodes contextual bindings made by the authenticator. These bindings are
	// controlled by the authenticator itself, and derive their trust from the WebAuthn Relying Party's assessment
	// of the security properties of the authenticator.
	AuthData []byte `json:"authData"`
	// The Format is the manner in which the signature is represented and the various contextual bindings are
	// incorporated into the attestation statement by the authenticator.
	Format string `json:"fmt"`
	// The Statement is a signed data object, containing statements about a public key credential itself and
	// the authenticator that created it.
	Statement AttestationStatement `json:"attStmt,omitempty"`
}

// UnmarshalAttestationObject unmarshals an attestation object from a slice of bytes. It expects a CBOR-encoded
// map.
func UnmarshalAttestationObject(raw []byte) (attestationObject *AttestationObject, remaining []byte, err error) {
	attestationObject = new(AttestationObject)

	decoder := cbor.NewDecoder(bytes.NewReader(raw))
	err = decoder.Decode(attestationObject)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidAttestationObject, err)
	}

	return attestationObject, raw[decoder.NumBytesRead():], nil
}
