// Package cose contains the subset of the CBOR Object Signing and Encryption (COSE) standard
// needed for webauthn.
package cose

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
)

// The Algorithm identifies a cryptographic algorithm as defined in
// https://www.iana.org/assignments/cose/cose.xhtml#algorithms.
type Algorithm int

const (
	// AlgorithmRS1 indicates RSASSA-PKCS1-v1_5 with SHA-1.
	AlgorithmRS1 Algorithm = -65535
	// AlgorithmRS512 indicates RSASSA-PKCS1-v1_5 with SHA-512.
	AlgorithmRS512 Algorithm = -259
	// AlgorithmRS384 indicates RSASSA-PKCS1-v1_5 with SHA-384.
	AlgorithmRS384 Algorithm = -258
	// AlgorithmRS256 indicates RSASSA-PKCS1-v1_5 with SHA-256.
	AlgorithmRS256 Algorithm = -257
	// AlgorithmPS512 indicates RSASSA-PSS with SHA-512.
	AlgorithmPS512 Algorithm = -39
	// AlgorithmPS384 indicates RSASSA-PSS with SHA-384.
	AlgorithmPS384 Algorithm = -38
	// AlgorithmPS256 indicates RSASSA-PSS with SHA-256.
	AlgorithmPS256 Algorithm = -37
	// AlgorithmES512 indicates ECDSA w/ SHA-512.
	AlgorithmES512 Algorithm = -36
	// AlgorithmES384 indicates ECDSA w/ SHA-384.
	AlgorithmES384 Algorithm = -35
	// AlgorithmEdDSA indicates EdDSA.
	AlgorithmEdDSA Algorithm = -8
	// AlgorithmES256 indicates ECDSA w/ SHA-256.
	AlgorithmES256 Algorithm = -7
)

// Hash returns the cryptographic Hash used by the algorithm.
func (alg Algorithm) Hash() crypto.Hash {
	switch alg {
	case AlgorithmRS1:
		return crypto.SHA1
	case AlgorithmRS512, AlgorithmPS512, AlgorithmES512:
		return crypto.SHA512
	case AlgorithmRS384, AlgorithmPS384, AlgorithmES384:
		return crypto.SHA384
	case AlgorithmRS256, AlgorithmPS256, AlgorithmES256:
		return crypto.SHA256
	case AlgorithmEdDSA:
		return 0 // hashing is already part of EdDSA itself
	default:
		return 0 // unknown
	}
}

// X509SignatureAlgorithm returns the corresponding x509.SignatureAlgorithm for the Algorithm.
func (alg Algorithm) X509SignatureAlgorithm() x509.SignatureAlgorithm {
	switch alg {
	case AlgorithmRS1:
		return x509.SHA1WithRSA
	case AlgorithmRS512:
		return x509.SHA512WithRSA
	case AlgorithmRS384:
		return x509.SHA384WithRSA
	case AlgorithmRS256:
		return x509.SHA256WithRSA
	case AlgorithmPS512:
		return x509.SHA512WithRSAPSS
	case AlgorithmPS384:
		return x509.SHA384WithRSAPSS
	case AlgorithmPS256:
		return x509.SHA256WithRSAPSS
	case AlgorithmES512:
		return x509.ECDSAWithSHA512
	case AlgorithmES384:
		return x509.ECDSAWithSHA384
	case AlgorithmEdDSA:
		return x509.PureEd25519
	case AlgorithmES256:
		return x509.ECDSAWithSHA256
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

// String returns the algorithm as a string.
func (alg Algorithm) String() string {
	switch alg {
	case AlgorithmRS1:
		return "RS1"
	case AlgorithmRS512:
		return "RS512"
	case AlgorithmRS384:
		return "RS384"
	case AlgorithmRS256:
		return "RS256"
	case AlgorithmPS512:
		return "PS512"
	case AlgorithmPS384:
		return "PS384"
	case AlgorithmPS256:
		return "PS256"
	case AlgorithmES512:
		return "ES512"
	case AlgorithmES384:
		return "ES384"
	case AlgorithmEdDSA:
		return "EdDSA"
	case AlgorithmES256:
		return "ES256"
	default:
		return "UNKNOWN"
	}
}

// Curve indicates the cryptographic elliptic curve used by an algorithm as defined in:
// https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
type Curve int

// Elliptic curves
const (
	CurveP256 Curve = iota + 1
	CurveP384
	CurveP521
	CurveX25519
	CurveX448
	CurveEd25519
	CurveEd448
	CurveSECP256K1
)

// EllipticCurve returns the elliptic.Curve for the given Curve.
func (curve Curve) EllipticCurve() (ellipticCurve elliptic.Curve, ok bool) {
	switch curve {
	case CurveP256:
		return elliptic.P256(), true
	case CurveP384:
		return elliptic.P384(), true
	case CurveP521:
		return elliptic.P521(), true
	default:
		return nil, false
	}
}

// String returns the curve as a string.
func (curve Curve) String() string {
	switch curve {
	case CurveP256:
		return "P-256"
	case CurveP384:
		return "P-384"
	case CurveP521:
		return "P-521"
	case CurveX25519:
		return "X25519"
	case CurveX448:
		return "X448"
	case CurveEd25519:
		return "Ed25519"
	case CurveEd448:
		return "Ed448"
	case CurveSECP256K1:
		return "secp256k1"
	default:
		return "UNKNOWN"
	}
}

// The KeyType indicates the encoding format used to encode a key.
type KeyType byte

const (
	// KeyTypeOctet is the key type (kty) used for EdDSA keys.
	KeyTypeOctet KeyType = iota + 1
	// KeyTypeElliptic is the key type (kty) used for ECDSA keys.
	KeyTypeElliptic
	// KeyTypeRSA is the key type (kty) used for RSA keys.
	KeyTypeRSA
)

// String returns the key type as a string.
func (kty KeyType) String() string {
	switch kty {
	case KeyTypeOctet:
		return "OKP"
	case KeyTypeElliptic:
		return "EC2"
	case KeyTypeRSA:
		return "RSA"
	default:
		return "UNKNOWN"
	}
}
