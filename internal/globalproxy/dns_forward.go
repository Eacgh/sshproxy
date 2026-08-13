package globalproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	dnsConnectionMaxIdle = 20 * time.Second
	dnsReuseTimeout      = time.Second
	customDNSConnections = 4
	// 自定义 DNS 查询失败后进入冷却期，期间所有查询直接回退到 Fake-IP
	// （域名交给 SSH 服务器解析）；冷却结束后自动重试，避免一次瞬态失败
	// 让整个会话永久降级，也不会让每个查询都白等超时。
	customDNSRetryInterval = 5 * time.Minute
)

type customDNSResolver struct {
	forwards []*forwardingDNSResolver
	next     atomic.Uint32
	fake     *fakeDNSResolver
	cache    *dnsNameCache
	logger   *slog.Logger
	// unavailableSince 记录最近一次查询失败的纳秒时间戳，0 表示当前可用。
	// 查询失败后进入 customDNSRetryInterval 冷却期，期间所有查询直接回退
	// 到 Fake-IP；冷却结束后恢复尝试，成功即清除时间戳。
	unavailableSince atomic.Int64
}

func newCustomDNSResolver(dialer Dialer, address string, fake *fakeDNSResolver, cache *dnsNameCache, logger *slog.Logger) *customDNSResolver {
	if logger == nil {
		logger = slog.Default()
	}
	resolver := &customDNSResolver{
		forwards: make([]*forwardingDNSResolver, customDNSConnections),
		fake:     fake,
		cache:    cache,
		logger:   logger,
	}
	for index := range resolver.forwards {
		resolver.forwards[index] = &forwardingDNSResolver{dialer: dialer, address: address}
	}
	return resolver
}

// inCooldown 报告自定义 DNS 是否仍处于失败冷却期。
func (r *customDNSResolver) inCooldown() bool {
	since := r.unavailableSince.Load()
	if since == 0 {
		return false
	}
	return time.Since(time.Unix(0, since)) < customDNSRetryInterval
}

// resolve 使用用户指定的 DNS 获得真实 IPv4，但只向 Windows 返回 Fake-IP。
// AAAA 和其他扩展记录返回空回答，避免远端没有 IPv6 时浏览器被真实 AAAA 卡住。
// 自定义 DNS 不可达时进入冷却期回退到 Fake-IP（域名交给 SSH 服务器解析），
// 冷却结束后自动重试，不阻塞页面。
func (r *customDNSResolver) resolve(ctx context.Context, payload []byte) ([]byte, error) {
	if r.inCooldown() {
		return r.fake.resolve(payload)
	}
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

	forward := r.forwards[(r.next.Add(1)-1)%uint32(len(r.forwards))]
	upstreamPayload, err := forward.resolve(ctx, payload)
	if err != nil {
		// 经 SSH 查询自定义 DNS 失败（服务器到该 DNS 不可达），降级为
		// 域名交给 SSH 服务器解析，保证页面仍然可用；保留最早的失败时间，
		// 避免并发失败不断把冷却窗口往后推。
		if r.unavailableSince.Load() == 0 {
			r.unavailableSince.Store(time.Now().UnixNano())
		}
		r.logger.Warn("自定义 DNS 经 SSH 查询失败，冷却期内回退到 SSH 服务器解析域名", "错误", err)
		return r.fake.resolve(payload)
	}
	r.unavailableSince.Store(0)
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
	errs := make([]error, 0, len(r.forwards))
	for _, forward := range r.forwards {
		if err := forward.close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

type forwardingDNSResolver struct {
	dialer  Dialer
	address string

	mu         sync.Mutex
	connection net.Conn
	lastUsed   time.Time
}

// resolve 把 DNS 数据封装为 DNS-over-TCP，并通过 SSH 访问用户指定的服务器。
// 所有查询复用同一条 TCP 连接，避免反复建立 SSH 通道。
func (r *forwardingDNSResolver) resolve(ctx context.Context, payload []byte) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.connection != nil && time.Since(r.lastUsed) >= dnsConnectionMaxIdle {
		r.connection.Close()
		r.connection = nil
	}
	if r.connection != nil {
		response, err := exchangeReusedDNS(ctx, r.connection, payload)
		if err == nil {
			r.lastUsed = time.Now()
			return response, nil
		}
		r.connection.Close()
		r.connection = nil
		if err := ctx.Err(); err != nil {
			return nil, err
		}
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
	r.lastUsed = time.Now()
	return response, nil
}

func exchangeReusedDNS(ctx context.Context, connection net.Conn, payload []byte) ([]byte, error) {
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= dnsReuseTimeout {
		return exchangeDNS(ctx, connection, payload)
	}
	reuseCtx, cancel := context.WithTimeout(ctx, dnsReuseTimeout)
	defer cancel()
	return exchangeDNS(reuseCtx, connection, payload)
}

func (r *forwardingDNSResolver) close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.connection == nil {
		return nil
	}
	err := r.connection.Close()
	r.connection = nil
	r.lastUsed = time.Time{}
	return err
}

// exchangeDNS 通过 SSH 通道交换一次 DNS-over-TCP 报文。
// SSH 通道不支持 SetDeadline（ssh: tcpChan: deadline not supported），
// 因此用带超时的上下文配合后台协程实现查询时限，超时后由调用方关闭通道。
func exchangeDNS(ctx context.Context, connection net.Conn, payload []byte) ([]byte, error) {
	type result struct {
		response []byte
		err      error
	}
	resultCh := make(chan result, 1)
	go func() {
		response, err := doExchangeDNS(connection, payload)
		resultCh <- result{response: response, err: err}
	}()
	select {
	case result := <-resultCh:
		return result.response, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func doExchangeDNS(connection net.Conn, payload []byte) ([]byte, error) {
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
