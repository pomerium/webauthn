package tpm

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetHardwareDetailsFromCertificate(t *testing.T) {
	bs, err := os.ReadFile("../testdata/attestationTPMSHA256Certificate.pem")
	require.NoError(t, err)
	block, _ := pem.Decode(bs)
	certificate, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	details, err := GetHardwareDetailsFromCertificate(certificate)
	assert.NoError(t, err)
	assert.Equal(t, &HardwareDetails{
		Manufacturer:    Vendor{"FIDO Alliance", VendorID{0xFF, 0xFF, 0xF1, 0xD0}},
		PartNumber:      "NPCT6xx",
		FirmwareVersion: "id:13",
	}, details)
}
