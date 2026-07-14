package globalproxy

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	fakeDNSAnswerTTL   = 60
	fakeDNSMappingTTL  = 24 * time.Hour
	fakeIPv4AddressMax = (1 << 16) - 2
)

type fakeDNSAddresses struct {
	ipv4 netip.Addr
	ipv6 netip.Addr
}

// fakeDNSResolver 给域名分配仅在本次运行中有效的保留地址。
// Windows 会立即拿到响应；真正建立 TCP 通道时再把域名交给 SSH 服务器解析，
// 因此不需要先经 SSH 查询公共 DNS，也不会把本机 DNS 请求泄漏到局域网。
type fakeDNSResolver struct {
	cache *dnsNameCache

	mu        sync.Mutex
	addresses map[string]fakeDNSAddresses
	next      uint32
}

func newFakeDNSResolver(cache *dnsNameCache) *fakeDNSResolver {
	return &fakeDNSResolver{
		cache:     cache,
		addresses: make(map[string]fakeDNSAddresses),
	}
}

func (r *fakeDNSResolver) resolve(payload []byte) ([]byte, error) {
	var query dnsmessage.Message
	if err := query.Unpack(payload); err != nil {
		return nil, fmt.Errorf("解析 DNS 查询失败：%w", err)
	}
	if query.Header.Response || len(query.Questions) == 0 {
		return nil, errors.New("收到的 DNS 数据不是有效查询")
	}

	response := newDNSResponse(query)
	for _, question := range query.Questions {
		if question.Class != dnsmessage.ClassINET ||
			(question.Type != dnsmessage.TypeA && question.Type != dnsmessage.TypeAAAA) {
			continue
		}
		name := normalizedDNSName(question.Name)
		if name == "" {
			continue
		}
		addresses, err := r.addressesFor(name)
		if err != nil {
			return nil, err
		}
		header := dnsmessage.ResourceHeader{
			Name:  question.Name,
			Type:  question.Type,
			Class: dnsmessage.ClassINET,
			TTL:   fakeDNSAnswerTTL,
		}
		if question.Type == dnsmessage.TypeA {
			response.Answers = append(response.Answers, dnsmessage.Resource{
				Header: header,
				Body:   &dnsmessage.AResource{A: addresses.ipv4.As4()},
			})
		} else {
			response.Answers = append(response.Answers, dnsmessage.Resource{
				Header: header,
				Body:   &dnsmessage.AAAAResource{AAAA: addresses.ipv6.As16()},
			})
		}
	}
	packed, err := response.Pack()
	if err != nil {
		return nil, fmt.Errorf("生成 Fake-IP DNS 响应失败：%w", err)
	}
	return packed, nil
}

func newDNSResponse(query dnsmessage.Message) dnsmessage.Message {
	return dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 query.Header.ID,
			Response:           true,
			OpCode:             query.Header.OpCode,
			RecursionDesired:   query.Header.RecursionDesired,
			RecursionAvailable: true,
		},
		Questions: append([]dnsmessage.Question(nil), query.Questions...),
	}
}

func normalizedDNSName(name dnsmessage.Name) string {
	return strings.ToLower(strings.TrimSuffix(name.String(), "."))
}

func (r *fakeDNSResolver) addressesFor(name string) (fakeDNSAddresses, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if addresses, ok := r.addresses[name]; ok {
		r.cache.store(name, addresses.ipv4, fakeDNSMappingTTL)
		r.cache.store(name, addresses.ipv6, fakeDNSMappingTTL)
		return addresses, nil
	}
	if r.next >= fakeIPv4AddressMax {
		return fakeDNSAddresses{}, errors.New("Fake-IP 地址池已经耗尽")
	}
	sequence := r.next + 1
	r.next++
	ipv4 := netip.AddrFrom4([4]byte{
		198,
		19,
		byte(sequence >> 8),
		byte(sequence),
	})
	var ipv6Bytes [16]byte
	ipv6Bytes[0] = 0xfd
	ipv6Bytes[1] = 0x01
	ipv6Bytes[12] = byte(sequence >> 24)
	ipv6Bytes[13] = byte(sequence >> 16)
	ipv6Bytes[14] = byte(sequence >> 8)
	ipv6Bytes[15] = byte(sequence)
	ipv6 := netip.AddrFrom16(ipv6Bytes)
	addresses := fakeDNSAddresses{ipv4: ipv4, ipv6: ipv6}
	r.addresses[name] = addresses
	r.cache.store(name, ipv4, fakeDNSMappingTTL)
	r.cache.store(name, ipv6, fakeDNSMappingTTL)
	return addresses, nil
}
