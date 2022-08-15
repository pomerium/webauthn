// Package tpm contains types and functions for interacting with TPM structures.
package tpm

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2"
)

// re-exported constants
const (
	TagAttestCertify = tpm2.TagAttestCertify
	GeneratedValue   = 0xFF544347
)

// ErrInvalidVendorID indicates that the vendor id is not valid.
var ErrInvalidVendorID = errors.New("invalid vendor ID")

// A VendorID is a 16 bit identifier for a vendor.
type VendorID [4]byte

// UnmarshalVendorID unmarshals a vendor id according to the TPMManufacturer format defined in 3.1.2 of
// https://www.trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf:
//
//	The value of the TPMManufacturer attribute MUST be the ASCII representation of the
//	hexadecimal value of the 4 byte vendor identifier defined in the TCG Vendor ID Registry[3]. Each
//	byte is represented individually as a two digit unsigned hexadecimal number using the characters
//	0-9 and A-F. The result is concatenated together to form an 8 character name which is appended
//	after the lower-case ASCII characters “id:”.
func UnmarshalVendorID(value string) (VendorID, error) {
	id, err := unmarshalTPMID(value)
	if err != nil {
		return VendorID{}, fmt.Errorf("%w: %s", ErrInvalidVendorID, err)
	}
	return id, nil
}

// String returns the VendorID as a string
func (id VendorID) String() string {
	buf := make([]byte, 0, 4)
	for _, b := range id {
		if b != 0 {
			buf = append(buf, b)
		}
	}
	return string(buf)
}

// A Vendor is an approved TPM vendor as defined by the Trusted Computing Group at
// https://trustedcomputinggroup.org/resource/vendor-id-registry/.
type Vendor struct {
	Name string
	ID   VendorID
}

// RegisteredVendors is the list of all known vendors.
var RegisteredVendors map[VendorID]Vendor

func init() {
	RegisteredVendors = make(map[VendorID]Vendor)
	for _, vendor := range []Vendor{
		{"AMD", VendorID{0x41, 0x4d, 0x44, 0x00}},
		{"Atmel", VendorID{0x41, 0x54, 0x4D, 0x4C}},
		{"Broadcom", VendorID{0x42, 0x52, 0x43, 0x4D}},
		{"Cisco", VendorID{0x43, 0x53, 0x43, 0x4F}},
		{"Flyslice Technologies", VendorID{0x46, 0x4C, 0x59, 0x53}},
		{"HPE", VendorID{0x48, 0x50, 0x45, 0x00}},
		{"IBM", VendorID{0x49, 0x42, 0x4d, 0x00}},
		{"Infineon", VendorID{0x49, 0x46, 0x58, 0x00}},
		{"Intel", VendorID{0x49, 0x4E, 0x54, 0x43}},
		{"Lenovo", VendorID{0x4C, 0x45, 0x4E, 0x00}},
		{"Microsoft", VendorID{0x4D, 0x53, 0x46, 0x54}},
		{"National Semiconductor", VendorID{0x4E, 0x53, 0x4D, 0x20}},
		{"Nationz", VendorID{0x4E, 0x54, 0x5A, 0x00}},
		{"Nuvoton Technology", VendorID{0x4E, 0x54, 0x43, 0x00}},
		{"Qualcomm", VendorID{0x51, 0x43, 0x4F, 0x4D}},
		{"SMSC", VendorID{0x53, 0x4D, 0x53, 0x43}},
		{"ST Microelectronics", VendorID{0x53, 0x54, 0x4D, 0x20}},
		{"Samsung", VendorID{0x53, 0x4D, 0x53, 0x4E}},
		{"Sinosun", VendorID{0x53, 0x4E, 0x53, 0x00}},
		{"Texas Instruments", VendorID{0x54, 0x58, 0x4E, 0x00}},
		{"Winbond", VendorID{0x57, 0x45, 0x43, 0x00}},
		{"Fuzhou Rockchip", VendorID{0x52, 0x4F, 0x43, 0x43}},
		{"Google", VendorID{0x47, 0x4F, 0x4F, 0x47}},

		// fake vendor :( https://github.com/fido-alliance/conformance-test-tools-resources/issues/537
		{"FIDO Alliance", VendorID{0xFF, 0xFF, 0xF1, 0xD0}},
	} {
		RegisteredVendors[vendor.ID] = vendor
	}
}

// AttestationData is TPM attested data, re-exported from the tpm2 package for a single import.
type AttestationData = tpm2.AttestationData

// UnmarshalAttestationData unmarshals TPM attestation data.
func UnmarshalAttestationData(raw []byte) (*AttestationData, error) {
	return tpm2.DecodeAttestationData(raw)
}

// Public is the TPM public key information, re-exported from the tpm2 package for a single import.
type Public = tpm2.Public

// UnmarshalPublic unmarshals the public data.
func UnmarshalPublic(raw []byte) (*Public, error) {
	pub, err := tpm2.DecodePublic(raw)
	if err != nil {
		return nil, err
	}
	return &pub, nil
}

func unmarshalTPMID(raw string) (id [4]byte, err error) {
	if len(raw) != 11 {
		return id, fmt.Errorf("expected 8 characters in %s", raw)
	}

	if !strings.HasPrefix(raw, "id:") {
		return id, fmt.Errorf("missing id prefix in %s", raw)
	}

	bs, err := hex.DecodeString(raw[3:])
	if err != nil {
		return id, err
	}

	copy(id[:], bs)
	return id, nil
}
