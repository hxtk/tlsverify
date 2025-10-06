package tlsverify

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"

	"github.com/maypok86/otter/v2"
)

var (
	ErrCRLRevoked = errors.New("certificate revoked via CRL")
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Cache[K comparable, V any] interface {
	Get(ctx context.Context, url K, loader otter.Loader[K, V]) (V, error)
}

var _ Cache[string, *x509.RevocationList] = (*otter.Cache[string, *x509.RevocationList])(nil)

type Config struct {
	Client HTTPClient

	CRLCache   Cache[string, *x509.RevocationList]
	OnCRLError func(error) error
}

func VerifyPeerCertificate(config Config) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	client := config.Client
	if client == nil {
		client = http.DefaultClient
	}

	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		leaf := verifiedChains[0][0]
		ctx := context.Background()

		for _, url := range leaf.CRLDistributionPoints {
			if err := checkCRL(ctx, &config, leaf, url); err != nil {
				if config.OnCRLError != nil {
					if e := config.OnCRLError(err); e != nil {
						return e
					}
				} else {
					return err
				}
			}
		}
		return nil
	}
}

func checkCRL(ctx context.Context, config *Config, leaf *x509.Certificate, url string) error {
	var crl *x509.RevocationList
	var err error

	if config.CRLCache != nil {
		val, e := config.CRLCache.Get(ctx, url, otter.LoaderFunc[string, *x509.RevocationList](func(ctx context.Context, key string) (*x509.RevocationList, error) {
			return fetchCRL(ctx, config.Client, key)
		}))
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

	for _, revoked := range crl.RevokedCertificateEntries {
		if revoked.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			return ErrCRLRevoked
		}
	}

	return nil
}

func fetchCRL(ctx context.Context, client HTTPClient, url string) (*x509.RevocationList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, err
	}

	return crl, nil
}
