package tpm

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

var (
	// ErrMissingHardwareDetails indicates that the TPM hardware details weren't found.
	ErrMissingHardwareDetails = errors.New("tpm: missing hardware details")
	// ErrInvalidHardwareDetails indicates that the TPM hardware details were invalid.
	ErrInvalidHardwareDetails = errors.New("tpm: invalid hardware details")
)

var (
	oidSAN                = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidTPMManufacturer    = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidTPMPartNumber      = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidTPMFirmwareVersion = asn1.ObjectIdentifier{2, 23, 133, 2, 3}

	// sanTagDirectoryName is the directoryName tag in the SAN field of an x509 certificate.
	sanTagDirectoryName = 4
)

// HardwareDetails are the manufacturer details about the TPM hardware.
type HardwareDetails struct {
	Manufacturer    Vendor
	PartNumber      string
	FirmwareVersion string
}

// GetHardwareDetailsFromCertificate gets the hardware details from an x509 certificate's Subject Alternative Name
// according to 3.2.9 of:
// https://www.trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
func GetHardwareDetailsFromCertificate(certificate *x509.Certificate) (*HardwareDetails, error) {
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(oidSAN) {
			var seq []asn1.RawValue
			rest, err := asn1.Unmarshal(extension.Value, &seq)
			if err != nil {
				return nil, err
			} else if len(rest) > 0 {
				return nil, fmt.Errorf("%w: unexpected trailing data in SAN extension",
					ErrInvalidHardwareDetails)
			}

			for _, value := range seq {
				if value.Tag == sanTagDirectoryName {
					var name pkix.RDNSequence
					_, err = asn1.Unmarshal(value.Bytes, &name)
					if err != nil {
						return nil, fmt.Errorf("%w: invalid RDN sequence in SAN directory name: %s",
							ErrInvalidHardwareDetails, err)
					}
					return GetHardwareDetailsFromRDNSequence(name)
				}
			}
		}
	}
	return nil, ErrMissingHardwareDetails
}

// GetHardwareDetailsFromRDNSequence gets the hardware details from Relative Distinguished Name sequence.
func GetHardwareDetailsFromRDNSequence(sequence pkix.RDNSequence) (*HardwareDetails, error) {
	details := new(HardwareDetails)
	for _, set := range sequence {
		for _, attribute := range set {
			str, ok := attribute.Value.(string)
			if !ok {
				continue
			}

			switch {
			case attribute.Type.Equal(oidTPMManufacturer):
				vendorID, err := UnmarshalVendorID(str)
				if err != nil {
					return nil, fmt.Errorf("%w: %s", ErrInvalidHardwareDetails, err)
				}

				vendor, ok := RegisteredVendors[vendorID]
				if !ok {
					return nil, fmt.Errorf("%w: unknown TPM vendor: %4X", ErrInvalidHardwareDetails, vendorID)
				}

				details.Manufacturer = vendor
			case attribute.Type.Equal(oidTPMPartNumber):
				details.PartNumber = str
			case attribute.Type.Equal(oidTPMFirmwareVersion):
				details.FirmwareVersion = str
			}
		}
	}

	switch {
	case details.Manufacturer.ID == VendorID{}:
		return nil, fmt.Errorf("%w: missing TPM manufacturer", ErrInvalidHardwareDetails)
	case details.PartNumber == "":
		return nil, fmt.Errorf("%w: missing TPM part number", ErrInvalidHardwareDetails)
	case details.FirmwareVersion == "":
		return nil, fmt.Errorf("%w: missing TPM firmware version", ErrInvalidHardwareDetails)
	}

	return details, nil
}
