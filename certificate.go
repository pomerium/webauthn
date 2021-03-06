package webauthn

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/pomerium/webauthn/android"
)

// AppleCertPool is the x509 certificate pool used to verify apple attestation.
var AppleCertPool = x509.NewCertPool()

func init() {
	if !AppleCertPool.AppendCertsFromPEM(AppleWebAuthnRootCAPEM) {
		panic("invalid apple webauthn root ca")
	}
}

var (
	errInvalidAndroidKey    = errors.New("invalid android key")
	errInvalidAppleNonce    = errors.New("invalid apple nonce")
	errMissingAAGUID        = errors.New("missing AAGUID")
	errMissingAndroidKey    = errors.New("missing android key")
	errMissingAppleNonce    = errors.New("missing apple nonce")
	errAAGUIDMarkedCritical = errors.New("AAGUID marked critical")
)

var (
	oidAAGUID         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}
	oidAIKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 3}
	oidAndroidKey     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}
	oidAppleNonce     = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}
)

// certificateHasAIK returns true if the certificate has the AIK extended key usage.
func certificateHasAIK(certificate *x509.Certificate) bool {
	for _, eku := range certificate.UnknownExtKeyUsage {
		if eku.Equal(oidAIKCertificate) {
			return true
		}
	}
	return false
}

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

func getCertificateAndroidKeyDescription(certificate *x509.Certificate) (*android.KeyDescription, error) {
	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(oidAndroidKey) {
			continue
		}

		keyDescription, _, err := android.UnmarshalKeyDescription(extension.Value)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", errInvalidAndroidKey, err)
		}
		return keyDescription, nil
	}
	return nil, errMissingAndroidKey
}
