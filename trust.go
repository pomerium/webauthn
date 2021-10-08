package webauthn

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pomerium/webauthn/fido"

	"github.com/pomerium/webauthn/httputil"
)

// A TrustAnchorProvider supplies trust anchors for verification.
type TrustAnchorProvider interface {
	GetTrustAnchors(
		ctx context.Context,
		attestationFormat AttestationFormat,
		attestationType AttestationType,
		aaguid AAGUID,
	) (*x509.CertPool, error)
}

// A TrustAnchorProviderFunc implements the TrustAnchorProvider using a function.
type TrustAnchorProviderFunc func(
	ctx context.Context,
	attestationFormat AttestationFormat,
	attestationType AttestationType,
	aaguid AAGUID,
) (*x509.CertPool, error)

// GetTrustAnchors calls the underlying function.
func (f TrustAnchorProviderFunc) GetTrustAnchors(
	ctx context.Context,
	attestationFormat AttestationFormat,
	attestationType AttestationType,
	aaguid AAGUID,
) (*x509.CertPool, error) {
	return f(ctx, attestationFormat, attestationType, aaguid)
}

type fidoMetadataServiceTrustAnchorConfig struct {
	serviceURL   string
	cacheDir     string
	cacheTTL     time.Duration
	roundTripper http.RoundTripper
}

// A FIDOMetadataServiceTrustAnchorOption customizes the config for the FIDOMetadataServiceTrustAnchorProvider.
type FIDOMetadataServiceTrustAnchorOption func(*fidoMetadataServiceTrustAnchorConfig)

// WithFIDOMetadataServiceCacheDir sets the cacheDir in the config.
func WithFIDOMetadataServiceCacheDir(cacheDir string) FIDOMetadataServiceTrustAnchorOption {
	return func(cfg *fidoMetadataServiceTrustAnchorConfig) {
		cfg.cacheDir = cacheDir
	}
}

// WithFIDOMetadataServiceCacheTTL sets the cacheTTL in the config.
func WithFIDOMetadataServiceCacheTTL(cacheTTL time.Duration) FIDOMetadataServiceTrustAnchorOption {
	return func(cfg *fidoMetadataServiceTrustAnchorConfig) {
		cfg.cacheTTL = cacheTTL
	}
}

// WithFIDOMetadataServiceHTTPRoundTripper sets the roundTripper in the config.
func WithFIDOMetadataServiceHTTPRoundTripper(roundTripper http.RoundTripper) FIDOMetadataServiceTrustAnchorOption {
	return func(cfg *fidoMetadataServiceTrustAnchorConfig) {
		cfg.roundTripper = roundTripper
	}
}

// WithFIDOMetadataServiceURL sets the serviceURL in the config.
func WithFIDOMetadataServiceURL(serviceURL string) FIDOMetadataServiceTrustAnchorOption {
	return func(cfg *fidoMetadataServiceTrustAnchorConfig) {
		cfg.serviceURL = serviceURL
	}
}

func getFIDOMetadataServiceTrustAnchorConfig(
	options ...FIDOMetadataServiceTrustAnchorOption,
) *fidoMetadataServiceTrustAnchorConfig {
	cfg := new(fidoMetadataServiceTrustAnchorConfig)
	WithFIDOMetadataServiceCacheDir(filepath.Join(os.TempDir(), "pomerium-webauthn-cache"))(cfg)
	WithFIDOMetadataServiceCacheTTL(time.Hour * 24)(cfg)
	WithFIDOMetadataServiceHTTPRoundTripper(http.DefaultTransport)(cfg)
	WithFIDOMetadataServiceURL("https://mds.fidoalliance.org")(cfg)
	for _, o := range options {
		o(cfg)
	}
	return cfg
}

// The FIDOMetadataServiceTrustAnchorProvider supplies trust anchors from the FIDO Metadata Service.
type FIDOMetadataServiceTrustAnchorProvider struct {
	cfg          *fidoMetadataServiceTrustAnchorConfig
	roundTripper http.RoundTripper

	mu         sync.RWMutex
	lastUpdate time.Time
	lookup     map[AAGUID]*x509.CertPool
}

// DefaultFIDOMetadataServiceTrustAnchorProvider is a FIDOMetadataServiceTrustAnchorProvider with the
// default options set.
var DefaultFIDOMetadataServiceTrustAnchorProvider = NewFIDOMetadataServiceTrustAnchorProvider()

// NewFIDOMetadataServiceTrustAnchorProvider creates a new FIDOMetadataServiceTrustAnchorProvider.
func NewFIDOMetadataServiceTrustAnchorProvider(
	options ...FIDOMetadataServiceTrustAnchorOption,
) *FIDOMetadataServiceTrustAnchorProvider {
	cfg := getFIDOMetadataServiceTrustAnchorConfig(options...)
	roundTripper := httputil.NewCachedRoundTripper(
		cfg.cacheDir,
		cfg.roundTripper,
		cfg.cacheTTL,
	)
	return &FIDOMetadataServiceTrustAnchorProvider{
		cfg:          cfg,
		roundTripper: roundTripper,
		lookup:       map[AAGUID]*x509.CertPool{},
	}
}

// GetTrustAnchors gets the trust anchors for attestation verification from the FIDO Metadata Service.
func (provider *FIDOMetadataServiceTrustAnchorProvider) GetTrustAnchors(
	ctx context.Context,
	attestationFormat AttestationFormat,
	attestationType AttestationType,
	aaguid AAGUID,
) (*x509.CertPool, error) {
	lookup, err := provider.getLookup(ctx)
	if err != nil {
		return nil, err
	}

	pool, ok := lookup[aaguid]
	if !ok {
		pool = x509.NewCertPool()
	}

	return pool, nil
}

func (provider *FIDOMetadataServiceTrustAnchorProvider) getLookup(
	ctx context.Context,
) (map[AAGUID]*x509.CertPool, error) {
	provider.mu.RLock()
	lookup := provider.lookup
	lastUpdate := provider.lastUpdate
	provider.mu.RUnlock()

	if lastUpdate.Add(provider.cfg.cacheTTL).After(time.Now()) {
		return lookup, nil
	}

	provider.mu.Lock()
	defer provider.mu.Unlock()

	if provider.lastUpdate.Add(provider.cfg.cacheTTL).After(time.Now()) {
		return provider.lookup, nil
	}

	lookup, err := provider.getLookupLocked(ctx)
	if err != nil {
		return nil, err
	}
	provider.lookup = lookup
	provider.lastUpdate = time.Now()

	return lookup, nil
}

func (provider *FIDOMetadataServiceTrustAnchorProvider) getLookupLocked(
	ctx context.Context,
) (map[AAGUID]*x509.CertPool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", provider.cfg.serviceURL, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: provider.roundTripper,
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()

	bs, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	payload, err := fido.UnmarshalMetadataBLOBPayload(string(bs))
	if err != nil {
		return nil, err
	}

	lookup := map[AAGUID]*x509.CertPool{}
	for _, entry := range payload.Entries {
		if !entry.AAGUID.Valid() {
			// ignore empty AAGUIDs
			continue
		}

		certificates, err := entry.MetadataStatement.ParseAttestationRootCertificates()
		if err != nil {
			// ignore invalid certificates
			continue
		}

		pool := x509.NewCertPool()
		for _, certificate := range certificates {
			pool.AddCert(certificate)
		}
		lookup[entry.AAGUID] = pool
	}

	return lookup, nil
}
