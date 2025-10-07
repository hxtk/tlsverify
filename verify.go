package tlsverify

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/maypok86/otter/v2"
)

var (
	ErrCRLRevoked   = errors.New("certificate revoked via CRL")
	ErrCRLFetch     = errors.New("error fetching CRL")
	ErrCRLParse     = errors.New("error parsing CRL")
	ErrCRLSignature = errors.New("the CRL signature didn't match its issuer")
)

// HTTPClient executes HTTP requests.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Cache stores a leaky key-value mapping of data put into it, with
// recalculation.
//
// This interface exposes a subset of [*otter.Cache], which deduplicates
// concurrent requests for the same key and optionally refreshes them
// in the background.
type Cache[K comparable, V any] interface {
	Get(ctx context.Context, key K, loader otter.Loader[K, V]) (V, error)
}

var _ Cache[string, *x509.RevocationList] = (*otter.Cache[string, *x509.RevocationList])(nil)

// CRLConfig specifies the tunable options for CRL verification.
type CRLConfig struct {
	// Client gets used to execute HTTP requests for fetching CRLs.
	//
	// If nil, VerifyCRL uses `http.DefaultClient` to execut its requests.
	Client HTTPClient

	// Timeout specifies the time budget for CRL verification, including any time
	// spent fetching CRLs if they didn't exist in the cache.
	//
	// The zero-value sets an infinite timeout.
	Timeout time.Duration

	// Cache stores the CRLs used for verification.
	//
	// Users of this parameter should take care with TTLs to ensure that
	// they do not cache a CRL long after a new CRL becomes available and
	// grant access based on stale certificate data.
	//
	// If nil, VerifyCRL re-fetches the CRL every time.
	Cache Cache[string, *x509.RevocationList]

	// OnError gets called for each error returned by the CRL verification
	// process, which includes all of the `ErrCRL*` errors exported by this package
	// as well as `context.DeadlineExceeded`.
	//
	// Returned errors may also pass `errors.Is` checks related to other error
	// values, but these may change at any time.
	//
	// Return `nil` to suppress an error and allow verification to proceed.
	// If this function returns a non-nil error, fail CRL verification.
	//
	// If nil, fail closed on all errors.
	OnError func(error) error
}

// VerifyCRL returns a function matching the signature required by `tls.Config.VerifyPeerCertificate`.
//
// It fetches the CRL and stores it in an in-memory cache if configured, for the entire certificate chain.
func VerifyCRL(config CRLConfig) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	client := config.Client
	if client == nil {
		client = http.DefaultClient
	}

	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(verifiedChains) < 1 {
			return fmt.Errorf("no verified chains found")
		}

		if len(verifiedChains[0]) < 2 {
			return nil // Don't check revocation on self-signed certificates.
		}

		ctx, cancel := context.WithTimeout(context.TODO(), config.Timeout)
		defer cancel()

		// Check the entire chain.
		for i := range len(verifiedChains) - 1 {
			cert := verifiedChains[0][i]
			issuer := verifiedChains[0][i+1]

			for _, url := range cert.CRLDistributionPoints {
				if err := checkCRL(ctx, &config, cert, issuer, url); err != nil {
					if config.OnError != nil {
						if e := config.OnError(err); e != nil {
							return e
						}
					} else {
						return err
					}
				}
			}
		}

		return nil
	}
}

func checkCRL(ctx context.Context, config *CRLConfig, cert, issuer *x509.Certificate, url string) error {
	var crl *x509.RevocationList
	var err error

	if config.Cache != nil {
		val, e := config.Cache.Get(
			ctx,
			url,
			otter.LoaderFunc[string, *x509.RevocationList](
				func(ctx context.Context, key string) (*x509.RevocationList, error) {
					return fetchCRL(ctx, config.Client, key)
				},
			),
		)
		if e != nil {
			return e
		}
		crl = val
	} else {
		crl, err = fetchCRL(ctx, config.Client, url)
		if err != nil {
			return err
		}
	}

	if err = crl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("%w: %w", ErrCRLSignature, err)
	}

	for _, revoked := range crl.RevokedCertificateEntries {
		if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return ErrCRLRevoked
		}
	}

	return nil
}

func fetchCRL(ctx context.Context, client HTTPClient, url string) (*x509.RevocationList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w: %s", ErrCRLFetch, err, url)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w: %s", ErrCRLFetch, err, url)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %w: %s", ErrCRLFetch, otter.ErrNotFound, url)
	}

	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w: %s", ErrCRLFetch, err, url)
	}
	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w: %s", ErrCRLParse, err, url)
	}

	return crl, nil
}
