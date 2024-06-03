package fido

import (
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v3/jwt"
)

// GlobalSignRootCAPEM is the Root CA used by the FIDO Alliance to sign the
// BLOB metadata service. Taken from https://valid.r3.roots.globalsign.com/.
//
//go:embed files/globalsign-root-ca-r3.pem
var GlobalSignRootCAPEM []byte

type (
	// AuthenticatorGetInfo describes supported versions, extensions, AAGUID of the device and its capabilities.
	AuthenticatorGetInfo map[string]interface{}
	// AuthenticatorStatus is the status of the authenticator model.
	AuthenticatorStatus string
	// The BiometricAccuracyDescriptor describes relevant accuracy/complexity aspects in the case of a biometric user
	// verification method, see [FIDOBiometricsRequirements].
	BiometricAccuracyDescriptor struct {
		SelfAttestedFRR float64 `json:"selfAttestedFRR"`
		SelfAttestedFAR float64 `json:"selfAttestedFAR"`
		MaxTemplates    int     `json:"maxTemplates"`
		MaxRetries      int     `json:"maxRetries"`
		BlockSlowdown   int     `json:"blockSlowdown"`
	}
	// BiometricStatusReport contains the current BiometricStatusReport of one of the authenticator’s biometric
	// component.
	BiometricStatusReport struct {
		CertLevel                        int    `json:"certLevel"`
		Modality                         string `json:"modality"`
		EffectiveDate                    string `json:"effectiveDate"`
		CertificationDescriptor          string `json:"certificationDescriptor"`
		CertificateNumber                string `json:"certificateNumber"`
		CertificationPolicyVersion       string `json:"certificationPolicyVersion"`
		CertificationRequirementsVersion string `json:"certificationRequirementsVersion"`
	}
	// The CodeAccuracyDescriptor describes the relevant accuracy/complexity aspects of passcode user verification
	// methods.
	CodeAccuracyDescriptor struct {
		Base          int `json:"base"`
		MinLength     int `json:"minLength"`
		MaxRetries    int `json:"maxRetries"`
		BlockSlowdown int `json:"blockSlowdown"`
	}
	// The DisplayPNGCharacteristicsDescriptor describes a PNG image characteristics as defined in the PNG [PNG] spec
	// for IHDR (image header) and PLTE (palette table)
	DisplayPNGCharacteristicsDescriptor struct {
		Width       int               `json:"width"`
		Height      int               `json:"height"`
		BitDepth    int               `json:"bitDepth"`
		ColorType   int               `json:"colorType"`
		Compression int               `json:"compression"`
		Filter      int               `json:"filter"`
		Interlace   int               `json:"interlace"`
		PLTE        []RGBPaletteEntry `json:"plte"`
	}
	// ECDAATrustAnchor is the ECDAA-Issuer’s trust anchor.
	ECDAATrustAnchor struct {
		X       string `json:"X"`
		Y       string `json:"Y"`
		C       string `json:"c"`
		SX      string `json:"sx"`
		SY      string `json:"sy"`
		G1Curve string `json:"G1Curve"`
	}
	// ExtensionDescriptor is the extension supported by the authenticator.
	ExtensionDescriptor struct {
		ID            string `json:"id"`
		Tag           int    `json:"tag"`
		Data          string `json:"data"`
		FailIfUnknown bool   `json:"fail_if_unknown"`
	}
	// MetadataBLOBPayload contains all metadata for each authenticator.
	MetadataBLOBPayload struct {
		LegalHeader string                     `json:"legalHeader"`
		No          int                        `json:"no"`
		NextUpdate  string                     `json:"nextUpdate"`
		Entries     []MetadataBLOBPayloadEntry `json:"entries"`
	}
	// MetadataBLOBPayloadEntry is a single entry in the MetadataBLOBPayload.
	MetadataBLOBPayloadEntry struct {
		AAID                                 string                  `json:"aaid"`
		AAGUID                               AAGUID                  `json:"aaguid"`
		AttestationCertificateKeyIdentifiers []string                `json:"attestationCertificateKeyIdentifiers"`
		MetadataStatement                    MetadataStatement       `json:"metadataStatement"`
		BiometricStatusReports               []BiometricStatusReport `json:"biometricStatusReports"`
		StatusReports                        []StatusReport          `json:"statusReports"`
		TimeOfLastStatusChange               string                  `json:"timeOfLastStatusChange"`
		RogueListURL                         string                  `json:"rogueListURL"`
		RogueListHash                        string                  `json:"rogueListHash"`
	}
	// MetadataStatement describes an authenticator.
	MetadataStatement struct {
		LegalHeader                          string                                `json:"legalHeader"`
		AAID                                 string                                `json:"aaid"`
		AAGUID                               AAGUID                                `json:"aaguid"`
		AttestationCertificateKeyIdentifiers []string                              `json:"attestationCertificateKeyIdentifiers"`
		Description                          string                                `json:"description"`
		AlternativeDescription               string                                `json:"alternativeDescription"`
		AuthenticatorVersion                 int                                   `json:"authenticatorVersion"`
		ProtocolFamily                       string                                `json:"protocolFamily"`
		Schema                               int                                   `json:"schema"`
		UPV                                  []Version                             `json:"upv"`
		AuthenticationAlgorithms             []string                              `json:"authenticationAlgorithms"`
		PublicKeyAlgAndEncodings             []string                              `json:"publicKeyAlgAndEncodings"`
		AttestationTypes                     []string                              `json:"attestationTypes"`
		UserVerificationDetails              []VerificationMethodANDCombinations   `json:"userVerificationDetails"`
		KeyProtection                        []string                              `json:"keyProtection"`
		IsKeyRestricted                      bool                                  `json:"isKeyRestricted"`
		IsFreshUserVerificationRequired      bool                                  `json:"isFreshUserVerificationRequired"`
		MatcherProtection                    []string                              `json:"matcherProtection"`
		CryptoStrength                       int                                   `json:"cryptoStrength"`
		AttachmentHint                       []string                              `json:"attachmentHint"`
		TCDisplay                            []string                              `json:"tcDisplay"`
		TCDisplayContentType                 string                                `json:"tcDisplayContentType"`
		TCDisplayPNGCharacteristics          []DisplayPNGCharacteristicsDescriptor `json:"tcDisplayPNGCharacteristics"`
		AttestationRootCertificates          []string                              `json:"attestationRootCertificates"`
		ECDAATrustAnchors                    []ECDAATrustAnchor                    `json:"ecdaaTrustAnchors"`
		Icon                                 string                                `json:"icon"`
		SupportedExtensions                  []ExtensionDescriptor                 `json:"supportedExtensions"`
		AuthenticatorGetInfo                 AuthenticatorGetInfo                  `json:"authenticatorGetInfo"`
	}
	// The PatternAccuracyDescriptor describes relevant accuracy/complexity aspects in the case that a pattern is used
	// as the user verification method.
	PatternAccuracyDescriptor struct {
		MinComplexity int `json:"minComplexity"`
		MaxRetries    int `json:"maxRetries"`
		BlockSlowdown int `json:"blockSlowdown"`
	}
	// The RGBPaletteEntry is an RGB three-sample tuple palette entry.
	RGBPaletteEntry struct {
		R int `json:"r"`
		G int `json:"g"`
		B int `json:"b"`
	}
	// StatusReport contains an AuthenticatorStatus and additional data associated with it, if any.
	StatusReport struct {
		Status                           AuthenticatorStatus `json:"status"`
		EffectiveDate                    string              `json:"effectiveDate"`
		Certificate                      string              `json:"certificate"`
		URL                              string              `json:"url"`
		CertificationDescriptor          string              `json:"certificationDescriptor"`
		CertificateNumber                string              `json:"certificateNumber"`
		CertificationPolicyVersion       string              `json:"certificationPolicyVersion"`
		CertificationRequirementsVersion string              `json:"certificationRequirementsVersion"`
	}
	// VerificationMethodANDCombinations describes a combination of the user verification methods that MUST be passed
	// by the user, in order to achieve successful user verification.
	VerificationMethodANDCombinations []VerificationMethodDescriptor
	// VerificationMethodDescriptor is a descriptor for a specific base user verification method as implemented by the
	// authenticator.
	VerificationMethodDescriptor struct {
		UserVerificationMethod string                      `json:"userVerificationMethod"`
		CADesc                 CodeAccuracyDescriptor      `json:"caDesc"`
		BADesc                 BiometricAccuracyDescriptor `json:"baDesc"`
		PADesc                 PatternAccuracyDescriptor   `json:"paDesc"`
	}
	// Version represents a generic version with major and minor fields.
	Version struct {
		Major int `json:"major"`
		Minor int `json:"minor"`
	}
)

// ParseAttestationRootCertificates parses the raw AttestationRootCertificates.
func (metadataStatement *MetadataStatement) ParseAttestationRootCertificates() ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	for _, rawCert := range metadataStatement.AttestationRootCertificates {
		bs, err := base64.StdEncoding.DecodeString(
			// remove spaces
			strings.NewReplacer(" ", "", "\r", "", "\n", "", "\t", "").Replace(rawCert),
		)
		if err != nil {
			return nil, err
		}

		certificate, err := x509.ParseCertificate(bs)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}
	return certificates, nil
}

// Authenticator Statuses as defined in:
// https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#authenticatorstatus-enum
const (
	AuthenticatorStatusNotFIDOCertified          = "NOT_FIDO_CERTIFIED"
	AuthenticatorStatusFIDOCertified             = "FIDO_CERTIFIED"
	AuthenticatorStatusUserVerificationBypass    = "USER_VERIFICATION_BYPASS" //nolint
	AuthenticatorStatusAttestationKeyCompromise  = "ATTESTATION_KEY_COMPROMISE"
	AuthenticatorStatusUserKeyRemoteCompromise   = "USER_KEY_REMOTE_COMPROMISE"
	AuthenticatorStatusUserKeyPhysicalCompromise = "USER_KEY_PHYSICAL_COMPROMISE"
	AuthenticatorStatusUpdateAvailable           = "UPDATE_AVAILABLE"
	AuthenticatorStatusRevoked                   = "REVOKED"
	AuthenticatorStatusSelfAssertionSubmitted    = "SELF_ASSERTION_SUBMITTED"
	AuthenticatorStatusFIDOCertifiedL1           = "FIDO_CERTIFIED_L1"
	AuthenticatorStatusFIDOCertifiedL1Plus       = "FIDO_CERTIFIED_L1plus"
	AuthenticatorStatusFIDOCertifiedL2           = "FIDO_CERTIFIED_L2"
	AuthenticatorStatusFIDOCertifiedL2Plus       = "FIDO_CERTIFIED_L2plus"
	AuthenticatorStatusFIDOCertifiedL3           = "FIDO_CERTIFIED_L3"
	AuthenticatorStatusFIDOCertifiedL3Plus       = "FIDO_CERTIFIED_L3plus"
)

type unmarshalConfig struct {
	rootCA *x509.CertPool
}

// An UnmarshalOption customizes the unmarshal config.
type UnmarshalOption func(*unmarshalConfig)

// WithRootCA sets the rootCA in the config.
func WithRootCA(rootCA *x509.CertPool) UnmarshalOption {
	return func(cfg *unmarshalConfig) {
		cfg.rootCA = rootCA
	}
}

func getConfig(options ...UnmarshalOption) *unmarshalConfig {
	defaultRootCA := x509.NewCertPool()
	defaultRootCA.AppendCertsFromPEM(GlobalSignRootCAPEM)
	cfg := new(unmarshalConfig)
	WithRootCA(defaultRootCA)(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

// UnmarshalMetadataBLOBPayload unmarshals a MetadataBLOBPayload.
func UnmarshalMetadataBLOBPayload(rawJWT string, options ...UnmarshalOption) (*MetadataBLOBPayload, error) {
	cfg := getConfig(options...)

	tok, err := jwt.ParseSigned(rawJWT)
	if err != nil {
		return nil, err
	}

	var chains [][]*x509.Certificate
	for _, hdr := range tok.Headers {
		hdrChains, err := hdr.Certificates(x509.VerifyOptions{
			Roots: cfg.rootCA,
		})
		if err != nil {
			return nil, err
		}
		chains = append(chains, hdrChains...)
	}
	if len(chains) == 0 || len(chains[0]) == 0 {
		return nil, fmt.Errorf("no x5c certificate found in BLOB payload")
	}

	var payload MetadataBLOBPayload
	err = tok.Claims(chains[0][0].PublicKey, &payload)
	if err != nil {
		return nil, err
	}

	return &payload, nil
}
