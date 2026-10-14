package browser

import (
	"crypto/tls"
	"errors"
	"fmt"

	utls "github.com/refraction-networking/utls"

	http "github.com/aarock1234/fphttp"
)

func (c *Client) pool(profile *Profile) (*http.Transport, error) {
	id := profile.descriptor.ID
	c.mu.Lock()
	defer c.mu.Unlock()

	if pool := c.pools[id]; pool != nil {
		return pool, nil
	}
	fingerprint := profile.Fingerprint()
	if c.config.Fingerprint != nil {
		fingerprint = c.config.Fingerprint.Clone()
	}
	if fingerprint == nil {
		return nil, errors.New("browser: profile does not provide a wire configuration")
	}
	fingerprint.ClientSessionCache = utls.NewLRUClientSessionCache(0)
	if err := fingerprint.Validate(); err != nil {
		return nil, fmt.Errorf("browser: validate profile %s: %w", id, err)
	}

	pool := c.template.Clone()
	if pool.TLSClientConfig == nil {
		pool.TLSClientConfig = &tls.Config{}
	}
	pool.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(0)
	pool.Fingerprint = fingerprint
	pool.DisableCompression = true
	if pool.Proxy != nil {
		pool.Proxy = selectedProxy(pool.Proxy)
	}
	c.pools[id] = pool

	return pool, nil
}
