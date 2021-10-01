package webauthn

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
)

var (
	errInvalidAppleNonce    = errors.New("invalid apple nonce")
	errMissingAAGUID        = errors.New("missing AAGUID")
	errMissingAppleNonce    = errors.New("missing apple nonce")
	errAAGUIDMarkedCritical = errors.New("AAGUID marked critical")
)

var (
	oidAAGUID     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}
	oidAppleNonce = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}
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

func getCertificateAppleNonce(certificate *x509.Certificate) ([]byte, error) {
	type appleAnonymousAttestation struct {
		Nonce []byte `asn1:"tag:1,explicit"`
	}

	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(oidAppleNonce) {
			continue
		}

		var value appleAnonymousAttestation
		_, err := asn1.Unmarshal(extension.Value, &value)
		if err != nil {
			return nil, errInvalidAppleNonce
		}
		return value.Nonce, nil
	}
	return nil, errMissingAppleNonce
}
