package globalproxy

import (
	"net/netip"
	"testing"
	"time"
)

func TestDNSNameCacheRestoresFakeIPDomain(t *testing.T) {
	cache := newDNSNameCache()
	cache.store("x.com", netip.MustParseAddr("198.19.0.1"), time.Minute)
	got, target, ok := cache.lookupTarget(netip.MustParseAddr("198.19.0.1"))
	if !ok || got != "x.com" {
		t.Fatalf("IP 对应域名为 %q, %v；期望 x.com, true", got, ok)
	}
	if target.IsValid() {
		t.Fatalf("默认 Fake-IP 不应包含真实连接目标：%s", target)
	}
}

func TestDNSNameCacheRemovesExpiredMapping(t *testing.T) {
	cache := newDNSNameCache()
	address := netip.MustParseAddr("198.19.0.2")
	cache.store("example.com", address, -time.Second)
	if _, _, ok := cache.lookupTarget(address); ok {
		t.Fatal("过期的 Fake-IP 映射没有删除")
	}
}
