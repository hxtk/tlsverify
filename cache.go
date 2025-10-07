package tlsverify

import (
	"crypto/x509"
	"math"
	"time"

	"github.com/maypok86/otter/v2"
)

// RefreshCRL defines a refresh policy that fetches the latest CRL at the time advertised
// by the Next Update, falling back to a TTL if no such value exists.
//
// This keeps hot CRLs fresh in the background so that a client never has to wait
// for a synchronous fetch.
//
// Most users should prefer this over ExpireCRL, and use a constant TTL for expiration
// or a size-based eviction policy.
func RefreshCRL(ttl time.Duration) otter.RefreshCalculator[string, *x509.RevocationList] {
	return otter.RefreshWritingFunc(func(entry otter.Entry[string, *x509.RevocationList]) time.Duration {
		duration := entry.Value.NextUpdate.Sub(time.Now())
		if duration > 0 {
			return duration
		} else {
			return ttl
		}
	})
}

// ExpireCRL defines an expiration policy that deletes a CRL after the next update
// should exist. The next client to request that CRL has to wait for a synchronous
// refresh.
//
// Unlike RefreshCRL, this policy doesn't cause work in the background.
func ExpireCRL(ttl time.Duration) otter.ExpiryCalculator[string, *x509.RevocationList] {
	return otter.ExpiryWritingFunc(func(entry otter.Entry[string, *x509.RevocationList]) time.Duration {
		duration := entry.Value.NextUpdate.Sub(time.Now())
		if duration > 0 {
			return duration
		} else {
			return ttl
		}
	})
}

// CRLWeigher approximates the size of a CRL as the size of the raw bytes.
//
// This can inform the cache's eviction policy if you use a cache with a maximum total
// weight to achieve a memory bounds.
func CRLWeigher(key string, value *x509.RevocationList) uint32 {
	weight := len(key)
	weight += len(value.Raw)

	if weight > math.MaxUint32 {
		return math.MaxUint32
	} else if weight < 0 {
		return 0
	}

	return uint32(weight)
}
