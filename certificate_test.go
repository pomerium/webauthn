package webauthn

import (
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_getCertificateAAGUID(t *testing.T) {
	random := rand.New(rand.NewSource(1))
	pub, priv, err := ed25519.GenerateKey(random)
	require.NoError(t, err)

	t.Run("missing", func(t *testing.T) {
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
		}
		bs, err := x509.CreateCertificate(random, tpl, tpl, pub, priv)
		require.NoError(t, err)

		certificate, err := x509.ParseCertificate(bs)
		require.NoError(t, err)

		_, err = getCertificateAAGUID(certificate)
		assert.ErrorIs(t, err, errMissingAAGUID)
	})

	t.Run("marked critical", func(t *testing.T) {
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			ExtraExtensions: []pkix.Extension{
				{Id: oidAAGUID, Critical: true},
			},
		}
		bs, err := x509.CreateCertificate(random, tpl, tpl, pub, priv)
		require.NoError(t, err)

		certificate, err := x509.ParseCertificate(bs)
		require.NoError(t, err)

		_, err = getCertificateAAGUID(certificate)
		assert.ErrorIs(t, err, errAAGUIDMarkedCritical)
	})
}
