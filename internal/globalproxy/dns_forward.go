package globalproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type customDNSResolver struct {
	forward *forwardingDNSResolver
	fake    *fakeDNSResolver
	cache   *dnsNameCache
}

func newCustomDNSResolver(dialer Dialer, address string, fake *fakeDNSResolver, cache *dnsNameCache) *customDNSResolver {
	return &customDNSResolver{
		forward: &forwardingDNSResolver{dialer: dialer, address: address},
		fake:    fake,
		cache:   cache,
	}
}

// resolve 使用用户指定的 DNS 获得真实 IPv4，但只向 Windows 返回 Fake-IP。
// AAAA 和其他扩展记录返回空回答，避免远端没有 IPv6 时浏览器被真实 AAAA 卡住。
func (r *customDNSResolver) resolve(ctx context.Context, payload []byte) ([]byte, error) {
	var query dnsmessage.Message
	if err := query.Unpack(payload); err != nil {
		return nil, fmt.Errorf("解析自定义 DNS 查询失败：%w", err)
	}
	if query.Header.Response || len(query.Questions) == 0 {
		return nil, errors.New("收到的 DNS 数据不是有效查询")
	}
	name := firstIPv4QuestionName(query.Questions)
	if name == "" {
		return emptyDNSResponse(query)
	}

	upstreamPayload, err := r.forward.resolve(ctx, payload)
	if err != nil {
		return nil, err
	}
	var upstream dnsmessage.Message
	if err := upstream.Unpack(upstreamPayload); err != nil {
		return nil, fmt.Errorf("解析自定义 DNS 响应失败：%w", err)
	}
	if upstream.Header.ID != query.Header.ID || !upstream.Header.Response {
		return nil, errors.New("自定义 DNS 返回了不匹配的响应")
	}
	if upstream.Header.RCode != dnsmessage.RCodeSuccess {
		return upstreamPayload, nil
	}

	var actualAddress netip.Addr
	var fakeAddress netip.Addr
	answers := make([]dnsmessage.Resource, 0, len(upstream.Answers))
	for _, answer := range upstream.Answers {
		resource, ok := answer.Body.(*dnsmessage.AResource)
		if !ok {
			if answer.Header.Type != dnsmessage.TypeAAAA {
				answers = append(answers, answer)
			}
			continue
		}
		if actualAddress.IsValid() {
			continue
		}
		actualAddress = netip.AddrFrom4(resource.A)
		addresses, err := r.fake.addressesFor(name)
		if err != nil {
			return nil, err
		}
		fakeAddress = addresses.ipv4
		answer.Body = &dnsmessage.AResource{A: fakeAddress.As4()}
		answer.Header.TTL = boundedCustomDNSTTL(answer.Header.TTL)
		answers = append(answers, answer)
		r.cache.storeResolved(
			name,
			fakeAddress,
			actualAddress,
			time.Duration(answer.Header.TTL)*time.Second,
		)
	}
	if !actualAddress.IsValid() {
		return emptyDNSResponse(query)
	}
	upstream.Questions = append([]dnsmessage.Question(nil), query.Questions...)
	upstream.Answers = answers
	upstream.Additionals = filterDNSAddressResources(upstream.Additionals)
	upstream.Header.AuthenticData = false
	packed, err := upstream.Pack()
	if err != nil {
		return nil, fmt.Errorf("生成自定义 DNS Fake-IP 响应失败：%w", err)
	}
	return packed, nil
}

func firstIPv4QuestionName(questions []dnsmessage.Question) string {
	for _, question := range questions {
		if question.Class == dnsmessage.ClassINET && question.Type == dnsmessage.TypeA {
			return normalizedDNSName(question.Name)
		}
	}
	return ""
}

func emptyDNSResponse(query dnsmessage.Message) ([]byte, error) {
	response := newDNSResponse(query)
	packed, err := response.Pack()
	if err != nil {
		return nil, fmt.Errorf("生成空 DNS 响应失败：%w", err)
	}
	return packed, nil
}

func filterDNSAddressResources(resources []dnsmessage.Resource) []dnsmessage.Resource {
	filtered := resources[:0]
	for _, resource := range resources {
		if resource.Header.Type != dnsmessage.TypeA && resource.Header.Type != dnsmessage.TypeAAAA {
			filtered = append(filtered, resource)
		}
	}
	return filtered
}

func boundedCustomDNSTTL(ttl uint32) uint32 {
	if ttl < 30 {
		return 30
	}
	if ttl > fakeDNSAnswerTTL {
		return fakeDNSAnswerTTL
	}
	return ttl
}

func (r *customDNSResolver) close() error {
	return r.forward.close()
}

type forwardingDNSResolver struct {
	dialer  Dialer
	address string

	mu         sync.Mutex
	connection net.Conn
}

// resolve 把 DNS 数据封装为 DNS-over-TCP，并通过 SSH 访问用户指定的服务器。
// 所有查询复用同一条 TCP 连接，避免反复建立 SSH 通道。
func (r *forwardingDNSResolver) resolve(ctx context.Context, payload []byte) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.connection != nil {
		response, err := exchangeDNS(ctx, r.connection, payload)
		if err == nil {
			return response, nil
		}
		r.connection.Close()
		r.connection = nil
	}

	connection, err := r.dialer.DialContext(ctx, "tcp", r.address)
	if err != nil {
		return nil, fmt.Errorf("通过 SSH 连接自定义 DNS %s 失败：%w", r.address, err)
	}
	response, err := exchangeDNS(ctx, connection, payload)
	if err != nil {
		connection.Close()
		return nil, fmt.Errorf("查询自定义 DNS %s 失败：%w", r.address, err)
	}
	r.connection = connection
	return response, nil
}

func (r *forwardingDNSResolver) close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.connection == nil {
		return nil
	}
	err := r.connection.Close()
	r.connection = nil
	return err
}

func exchangeDNS(ctx context.Context, connection net.Conn, payload []byte) ([]byte, error) {
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, err
	}
	header := make([]byte, 2)
	packet := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(packet, uint16(len(payload)))
	copy(packet[2:], payload)
	if err := writeAll(connection, packet); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(connection, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header))
	if length == 0 {
		return nil, errors.New("自定义 DNS 返回了空响应")
	}
	response := make([]byte, length)
	if _, err := io.ReadFull(connection, response); err != nil {
		return nil, err
	}
	return response, nil
}
