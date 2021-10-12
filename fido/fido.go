// Package fido contains functionality related to FIDO devices.
package fido

import (
	"crypto/subtle"
	"encoding/json"

	"github.com/google/uuid"
)

// AAGUIDSize is the number of bytes of an AAGUID.
const AAGUIDSize = 16

// AAGUID is the Authenticator Attestation GUID.
type AAGUID [AAGUIDSize]byte

// ParseAAGUID parses an AAGUID from a string.
func ParseAAGUID(str string) (AAGUID, error) {
	id, err := uuid.Parse(str)
	return AAGUID(id), err
}

// Equals returns true if the AAGUIDs match.
func (aaguid AAGUID) Equals(other AAGUID) bool {
	return subtle.ConstantTimeCompare(aaguid[:], other[:]) == 1
}

// MarshalJSON marshals the AAGUID into JSON.
func (aaguid AAGUID) MarshalJSON() ([]byte, error) {
	return json.Marshal(aaguid.String())
}

// String returns the AAGUID as a string.
func (aaguid AAGUID) String() string {
	return uuid.UUID(aaguid).String()
}

// UnmarshalJSON unmarshals raw JSON into an AAGUID.
func (aaguid *AAGUID) UnmarshalJSON(raw []byte) error {
	var str string
	err := json.Unmarshal(raw, &str)
	if err != nil {
		return err
	}
	*aaguid, err = ParseAAGUID(str)
	return err
}

// Valid returns true if the AAGUID is not all zeroes.
func (aaguid AAGUID) Valid() bool {
	return aaguid != AAGUID{}
}
