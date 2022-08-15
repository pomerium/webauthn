package webauthn

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// RPIDHashSize is the number of bytes in a SHA256 Hash of the RP ID.
const RPIDHashSize = sha256.Size

// RPIDHash is the SHA-256 hash of the RP ID.
type RPIDHash [RPIDHashSize]byte

// MarshalJSON marshals the RPIDHash for JSON.
func (rpidhash RPIDHash) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(rpidhash[:]))
}

// ErrInvalidAuthenticatorData indicates the authenticator data is invalid.
var ErrInvalidAuthenticatorData = errors.New("invalid authenticator data")

// The AuthenticatorData encodes contextual bindings made by the authenticator. These bindings are controlled by the
// authenticator itself, and derive their trust from the WebAuthn Relying Party's assessment of the security
// properties of the authenticator.
type AuthenticatorData struct {
	// RPIDHash is the SHA-256 hash of the RP ID the credential is scoped to.
	RPIDHash RPIDHash
	// Flags are the authenticator flags.
	Flags AuthenticatorFlags
	// SignCount is the signature counter, 32-bit unsigned big-endian integer.
	SignCount uint32
	// AttestedCredentialData is the attested credential data (if present).
	AttestedCredentialData *AttestedCredentialData
	// Extensions are extension-defined authenticator data. This is a CBOR map with extension identifiers as keys,
	// and authenticator extension outputs as values.
	Extensions []byte
}

// UnmarshalAuthenticatorData unmarshals AuthenticatorData according to the data layout described in:
// https://www.w3.org/TR/webauthn-2/#authenticator-data.
//
//	rpIdHash: 32 bytes
//	flags: 1 byte, bitmask
//	signCount: 4 bytes, 32-bit unsigned big-endian integer
//	attestedCredentialData: variable
//	extensions: variable, cbor map
func UnmarshalAuthenticatorData(raw []byte) (data *AuthenticatorData, remaining []byte, err error) {
	data = new(AuthenticatorData)

	// unmarshal rpIdHash
	if len(raw) < RPIDHashSize {
		return nil, nil, fmt.Errorf("%w: missing RPIDHash", ErrInvalidAuthenticatorData)
	}
	copy(data.RPIDHash[:], raw[:RPIDHashSize])
	raw = raw[RPIDHashSize:]

	// unmarshal flags
	if len(raw) < AuthenticatorFlagsSize {
		return nil, nil, fmt.Errorf("%w: missing flags", ErrInvalidAuthenticatorData)
	}
	data.Flags = AuthenticatorFlags(raw[0])
	raw = raw[AuthenticatorFlagsSize:]

	// unmarshal sign count
	if len(raw) < 4 {
		return nil, nil, fmt.Errorf("%w: missing sign count", ErrInvalidAuthenticatorData)
	}
	data.SignCount = binary.BigEndian.Uint32(raw[:4])
	raw = raw[4:]

	// unmarshal attested credential data
	if data.Flags.AttestedCredentialDataIncluded() {
		data.AttestedCredentialData, raw, err = UnmarshalAttestedCredentialData(raw)
		if err != nil {
			return nil, nil, err
		}
	}

	// unmarshal extension data
	if data.Flags.ExtensionDataIncluded() {
		data.Extensions, raw, err = extractCBOR(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: missing extensions", ErrInvalidAuthenticatorData)
		}
	}

	return data, raw, nil
}

// Marshal marshals authenticator data according to the format defined in Unmarshal.
func (authenticatorData *AuthenticatorData) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	if err := write(&buf, authenticatorData.RPIDHash[:]...); err != nil {
		return nil, err
	}
	if err := write(&buf, byte(authenticatorData.Flags)); err != nil {
		return nil, err
	}
	if err := writeUint32(&buf, authenticatorData.SignCount); err != nil {
		return nil, err
	}
	if authenticatorData.Flags.AttestedCredentialDataIncluded() {
		bs, err := authenticatorData.AttestedCredentialData.Marshal()
		if err != nil {
			return nil, err
		}
		if err := write(&buf, bs...); err != nil {
			return nil, err
		}
	}
	if authenticatorData.Flags.ExtensionDataIncluded() {
		if err := write(&buf, authenticatorData.Extensions...); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}
