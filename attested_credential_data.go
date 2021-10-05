package webauthn

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// AAGUIDSize is the number of bytes of an AAGUID in the AttestedCredentialData.
const AAGUIDSize = 16

// AAGUID is the Authenticator Attestation GUID.
type AAGUID [AAGUIDSize]byte

func newRandomAAGUID() AAGUID {
	var aaguid AAGUID
	_, err := io.ReadFull(rand.Reader, aaguid[:])
	if err != nil {
		panic(err)
	}
	return aaguid
}

// Equals returns true if the AAGUIDs match.
func (aaguid AAGUID) Equals(other AAGUID) bool {
	return subtle.ConstantTimeCompare(aaguid[:], other[:]) == 1
}

// ErrInvalidAttestedCredentialData indicates the attested credential data is invalid.
var ErrInvalidAttestedCredentialData = errors.New("invalid attested credential data")

// AttestedCredentialData is added to the authenticator data when generating an attestation object for a given
// credential.
type AttestedCredentialData struct {
	// AAGUID is the AAGUID of the authenticator.
	AAGUID AAGUID
	// The CredentialID is a probabilistically-unique byte sequence identifying a public key credential source and
	// its authentication assertions.
	CredentialID []byte
	// CredentialPublicKey is the credential public key encoded in COSE_Key format.
	CredentialPublicKey []byte
}

// UnmarshalAttestedCredentialData unmarshals an AttestedCredentialData according to the data layout described in
// https://www.w3.org/TR/webauthn-2/#sctn-attested-credential-data:
//
//     aaguid: 16 bytes
//     credentialIdLength: 2 bytes, 16-bit unsigned big-endian = L
//     credentialId: L bytes
//     credentialPublicKey: variable, CTAP2 canonical CBOR encoding form
//
func UnmarshalAttestedCredentialData(raw []byte) (data *AttestedCredentialData, remaining []byte, err error) {
	data = new(AttestedCredentialData)

	// unmarshal AAGUID
	if len(raw) < AAGUIDSize {
		return nil, nil, fmt.Errorf("%w: missing AAGUID", ErrInvalidAttestedCredentialData)
	}
	copy(data.AAGUID[:], raw[:AAGUIDSize])
	raw = raw[AAGUIDSize:]

	// unmarshal credential id
	if len(raw) < 2 {
		return nil, nil, fmt.Errorf("%w: missing credential id length", ErrInvalidAttestedCredentialData)
	}
	credentialIDLength := int(binary.BigEndian.Uint16(raw[:2]))
	raw = raw[2:]
	if len(raw) < credentialIDLength {
		return nil, nil, fmt.Errorf("%w: missing credential id", ErrInvalidAttestedCredentialData)
	}
	data.CredentialID = raw[:credentialIDLength]
	raw = raw[credentialIDLength:]

	// unmarshal credential public key
	data.CredentialPublicKey, raw, err = extractCBOR(raw)
	if err != nil {
		return nil, nil, err
	}

	return data, raw, nil
}

// Marshal marshals the attested credential data in the format described in Unmarshal.
func (attestedCredentialData *AttestedCredentialData) Marshal() ([]byte, error) {
	if attestedCredentialData == nil {
		return nil, fmt.Errorf("cannot marshal a nil attested credential")
	}

	var buf bytes.Buffer
	if err := write(&buf, attestedCredentialData.AAGUID[:]...); err != nil {
		return nil, err
	}
	if err := writeUint16(&buf, uint16(len(attestedCredentialData.CredentialID))); err != nil {
		return nil, err
	}
	if err := write(&buf, attestedCredentialData.CredentialID...); err != nil {
		return nil, err
	}
	if err := write(&buf, attestedCredentialData.CredentialPublicKey...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
