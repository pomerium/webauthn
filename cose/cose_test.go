package cose

import (
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAlgorithm_String(t *testing.T) {
	type testCase struct {
		algorithm Algorithm
		expected  string
	}
	testCases := []testCase{
		{0, "UNKNOWN"},
		{AlgorithmRS1, "RS1"},
		{AlgorithmRS512, "RS512"},
		{AlgorithmRS384, "RS384"},
		{AlgorithmRS256, "RS256"},
		{AlgorithmPS512, "PS512"},
		{AlgorithmPS384, "PS384"},
		{AlgorithmPS256, "PS256"},
		{AlgorithmES512, "ES512"},
		{AlgorithmES384, "ES384"},
		{AlgorithmEdDSA, "EdDSA"},
		{AlgorithmES256, "ES256"},
	}
	for _, tc := range testCases {
		assert.Equal(t, tc.expected, tc.algorithm.String())
	}
}

func TestCurve_EllipticCurve(t *testing.T) {
	type testCase struct {
		curve         Curve
		expectedCurve elliptic.Curve
		expectedOK    bool
	}
	testCases := []testCase{
		{CurveP256, elliptic.P256(), true},
		{CurveP384, elliptic.P384(), true},
		{CurveP521, elliptic.P521(), true},
		{CurveX25519, nil, false},
		{CurveX448, nil, false},
		{CurveEd25519, nil, false},
		{CurveEd448, nil, false},
		{CurveSECP256K1, nil, false},
	}
	for _, tc := range testCases {
		ec, ok := tc.curve.EllipticCurve()
		assert.Equal(t, tc.expectedCurve, ec)
		assert.Equal(t, tc.expectedOK, ok)
	}
}

func TestCurve_String(t *testing.T) {
	type testCase struct {
		curve    Curve
		expected string
	}
	testCases := []testCase{
		{0, "UNKNOWN"},
		{CurveP256, "P-256"},
		{CurveP384, "P-384"},
		{CurveP521, "P-521"},
		{CurveX25519, "X25519"},
		{CurveX448, "X448"},
		{CurveEd25519, "Ed25519"},
		{CurveEd448, "Ed448"},
		{CurveSECP256K1, "secp256k1"},
	}
	for _, tc := range testCases {
		assert.Equal(t, tc.expected, tc.curve.String())
	}
}

func TestKeyType_String(t *testing.T) {
	type testCase struct {
		keyType  KeyType
		expected string
	}
	testCases := []testCase{
		{0, "UNKNOWN"},
		{KeyTypeOctet, "OKP"},
		{KeyTypeElliptic, "EC2"},
		{KeyTypeRSA, "RSA"},
	}
	for _, tc := range testCases {
		assert.Equal(t, tc.expected, tc.keyType.String())
	}
}
