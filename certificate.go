package webauthn

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
)

var (
	errMissingAAGUID        = errors.New("missing AAGUID")
	errAAGUIDMarkedCritical = errors.New("AAGUID marked critical")
)

var (
	oidAAGUID         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}
	oidAIKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 3}
)

func getCertificateAAGUID(certificate *x509.Certificate) (AAGUID, error) {
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(oidAAGUID) {
			if extension.Critical {
				return AAGUID{}, errAAGUIDMarkedCritical
			}

			var aaguid AAGUID
			_, err := asn1.Unmarshal(extension.Value, &aaguid)
			if err != nil {
				return aaguid, nil
			}
		}
	}
	return AAGUID{}, errMissingAAGUID
}

// certificateHasAIK returns true if the certificate has the AIK extended key usage.
func certificateHasAIK(certificate *x509.Certificate) bool {
	for _, eku := range certificate.UnknownExtKeyUsage {
		if eku.Equal(oidAIKCertificate) {
			return true
		}
	}
	return false
}
