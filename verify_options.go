package webauthn

type verifyConfig struct {
	allowNone, allowSelf bool
	trustAnchorProvider  TrustAnchorProvider
}

// A VerifyOption customizes how verification is performed.
type VerifyOption func(*verifyConfig)

// WithVerifyAllowNone sets allowNone in the config.
func WithVerifyAllowNone(allowNone bool) VerifyOption {
	return func(cfg *verifyConfig) {
		cfg.allowNone = allowNone
	}
}

// WithVerifyAllowSelf sets allowSelf in the config.
func WithVerifyAllowSelf(allowSelf bool) VerifyOption {
	return func(cfg *verifyConfig) {
		cfg.allowSelf = allowSelf
	}
}

// WithVerifyTrustAnchorProvider sets trustAnchorProvider in the config.
func WithVerifyTrustAnchorProvider(trustAnchorProvider TrustAnchorProvider) VerifyOption {
	return func(cfg *verifyConfig) {
		cfg.trustAnchorProvider = trustAnchorProvider
	}
}

func getVerifyConfig(options ...VerifyOption) (*verifyConfig, error) {
	cfg := new(verifyConfig)
	WithVerifyAllowNone(false)(cfg)
	WithVerifyAllowSelf(false)(cfg)
	WithVerifyTrustAnchorProvider(DefaultFIDOMetadataServiceTrustAnchorProvider)(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg, nil
}
