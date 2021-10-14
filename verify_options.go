package webauthn

type verifyConfig struct {
	allowedFormats map[AttestationFormat]struct{}
	allowedTypes   map[AttestationType]struct{}
}

// A VerifyOption customizes how verification is performed.
type VerifyOption func(*verifyConfig)

// WithVerifyAllowedFormats sets the allowedFormats in the verify config.
func WithVerifyAllowedFormats(allowedFormats ...AttestationFormat) VerifyOption {
	return func(cfg *verifyConfig) {
		cfg.allowedFormats = map[AttestationFormat]struct{}{}
		for _, allowedFormat := range allowedFormats {
			cfg.allowedFormats[allowedFormat] = struct{}{}
		}
	}
}

// WithVerifyAllowedTypes sets the allowedTypes in the verify config.
func WithVerifyAllowedTypes(allowedTypes ...AttestationType) VerifyOption {
	return func(cfg *verifyConfig) {
		cfg.allowedTypes = map[AttestationType]struct{}{}
		for _, allowedType := range allowedTypes {
			cfg.allowedTypes[allowedType] = struct{}{}
		}
	}
}

func getVerifyConfig(options ...VerifyOption) (*verifyConfig, error) {
	cfg := new(verifyConfig)
	WithVerifyAllowedFormats(AllAttestationFormats...)(cfg)
	WithVerifyAllowedTypes(AllAttestationTypes...)(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg, nil
}
