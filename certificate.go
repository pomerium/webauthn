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
	oidAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}
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
