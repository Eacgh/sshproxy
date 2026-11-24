package globalproxy

import (
	"net/netip"
	"sync"
	"time"
)

const maxDNSCacheEntries = 2048

type dnsNameEntry struct {
	name          string
	connectTarget netip.Addr
	expiresAt     time.Time
}

// dnsNameCache 记录 Fake-IP 对应的域名，或者自定义 DNS 返回的真实 IPv4。
type dnsNameCache struct {
	mu      sync.Mutex
	entries map[netip.Addr]dnsNameEntry
}

func (c *dnsNameCache) storeResolved(name string, fakeAddress, connectTarget netip.Addr, ttl time.Duration) {
	now := time.Now()
	c.mu.Lock()
	c.pruneExpiredLocked(now)
	c.entries[fakeAddress.Unmap()] = dnsNameEntry{
		name:          name,
		connectTarget: connectTarget.Unmap(),
		expiresAt:     now.Add(ttl),
	}
	c.mu.Unlock()
}

func newDNSNameCache() *dnsNameCache {
	return &dnsNameCache{entries: make(map[netip.Addr]dnsNameEntry)}
}

func (c *dnsNameCache) store(name string, address netip.Addr, ttl time.Duration) {
	now := time.Now()
	c.mu.Lock()
	c.pruneExpiredLocked(now)
	c.entries[address.Unmap()] = dnsNameEntry{
		name:      name,
		expiresAt: now.Add(ttl),
	}
	c.mu.Unlock()
}

func (c *dnsNameCache) pruneExpiredLocked(now time.Time) {
	if len(c.entries) < maxDNSCacheEntries {
		return
	}
	for k, entry := range c.entries {
		if !now.Before(entry.expiresAt) {
			delete(c.entries, k)
		}
	}
}

func (c *dnsNameCache) lookupTarget(address netip.Addr) (string, netip.Addr, bool) {
	address = address.Unmap()
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[address]
	if !ok {
		return "", netip.Addr{}, false
	}
	if !now.Before(entry.expiresAt) {
		delete(c.entries, address)
		return "", netip.Addr{}, false
	}
	return entry.name, entry.connectTarget, true
}
