package webauthn

import (
	"crypto/x509"
	"encoding/asn1"
)

var (
	oidAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}
)

func getCertificateAAGUID(certificate *x509.Certificate) AAGUID {

}
