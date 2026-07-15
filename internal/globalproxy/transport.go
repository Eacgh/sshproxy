package globalproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

const dnsQueryTimeout = 5 * time.Second

// sshTransport 让 tun2socks 直接复用 SSH Manager，避免本机 SOCKS 流量再次进入虚拟网卡。
// 普通 UDP 会被拒绝；DNS 在本机用 Fake-IP 回答，真实域名只交给 SSH 服务器解析。
type sshTransport struct {
	dialer      Dialer
	logger      *slog.Logger
	dnsNames    *dnsNameCache
	fakeDNS     *fakeDNSResolver
	customDNS   *customDNSResolver
	dialGuard   *dialGuard
	udpWarnOnce sync.Once
}

func newSSHTransport(dialer Dialer, dnsServer string, logger *slog.Logger) *sshTransport {
	if logger == nil {
		logger = slog.Default()
	}
	dnsNames := newDNSNameCache()
	transport := &sshTransport{
		dialer:    dialer,
		logger:    logger,
		dnsNames:  dnsNames,
		fakeDNS:   newFakeDNSResolver(dnsNames),
		dialGuard: newDialGuard(),
	}
	if dnsServer != "" {
		transport.customDNS = newCustomDNSResolver(dialer, dnsServer, transport.fakeDNS, dnsNames)
	}
	return transport
}

func (t *sshTransport) DialContext(ctx context.Context, metadata *M.Metadata) (net.Conn, error) {
	return t.dialContext(ctx, metadata, "")
}

func (t *sshTransport) DialContextWithServerName(ctx context.Context, metadata *M.Metadata, serverName string) (net.Conn, error) {
	return t.dialContext(ctx, metadata, serverName)
}

func (t *sshTransport) dialContext(ctx context.Context, metadata *M.Metadata, serverName string) (net.Conn, error) {
	if metadata == nil || !metadata.DstIP.IsValid() || metadata.DstPort == 0 {
		return nil, errors.New("全局代理收到无效的 TCP 目标")
	}
	if metadata.DstPort == 53 {
		if t.customDNS != nil {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return newDNSTCPConn(t.customDNS.resolve), nil
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return newFakeDNSTCPConn(t.fakeDNS.resolve), nil
	}
	target := t.targetAddress(metadata, serverName)
	release, err := t.dialGuard.acquire(ctx, target)
	if err != nil {
		return nil, err
	}
	defer release()
	connection, err := t.dialer.DialContext(ctx, "tcp", target)
	t.dialGuard.record(target, err)
	return connection, err
}

func (t *sshTransport) targetAddress(metadata *M.Metadata, serverName string) string {
	target := metadata.DestinationAddress()
	if name, resolvedAddress, ok := t.dnsNames.lookupTarget(metadata.DstIP); ok {
		if resolvedAddress.IsValid() {
			return net.JoinHostPort(resolvedAddress.String(), fmt.Sprint(metadata.DstPort))
		}
		return net.JoinHostPort(name, fmt.Sprint(metadata.DstPort))
	}
	if validServerName(serverName) {
		target = net.JoinHostPort(serverName, fmt.Sprint(metadata.DstPort))
	}
	return target
}

func (t *sshTransport) mappedServerName(metadata *M.Metadata) (string, bool) {
	if metadata == nil || !metadata.DstIP.IsValid() {
		return "", false
	}
	name, _, ok := t.dnsNames.lookupTarget(metadata.DstIP)
	return name, ok
}

func (t *sshTransport) DialUDP(metadata *M.Metadata) (net.PacketConn, error) {
	if metadata == nil || metadata.DstPort != 53 {
		t.udpWarnOnce.Do(func() {
			t.logger.Warn("当前全局模式只支持 TCP；已阻止非 DNS 的 UDP 流量以避免绕过 SSH")
		})
		return nil, errors.New("当前全局模式暂不支持非 DNS UDP 流量")
	}
	if t.customDNS != nil {
		return newDNSPacketConn(t.customDNS.resolve), nil
	}
	return newFakeDNSPacketConn(t.fakeDNS.resolve), nil
}

func (t *sshTransport) Close() {
	if t.customDNS != nil {
		_ = t.customDNS.close()
	}
}

func newFakeDNSTCPConn(resolver func([]byte) ([]byte, error)) net.Conn {
	return newDNSTCPConn(func(_ context.Context, payload []byte) ([]byte, error) {
		return resolver(payload)
	})
}

func newDNSTCPConn(resolver func(context.Context, []byte) ([]byte, error)) net.Conn {
	client, server := net.Pipe()
	go serveDNSTCP(server, resolver)
	return client
}

func serveDNSTCP(connection net.Conn, resolver func(context.Context, []byte) ([]byte, error)) {
	defer connection.Close()
	header := make([]byte, 2)
	for {
		if _, err := io.ReadFull(connection, header); err != nil {
			return
		}
		length := int(binary.BigEndian.Uint16(header))
		if length == 0 {
			return
		}
		query := make([]byte, length)
		if _, err := io.ReadFull(connection, query); err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), dnsQueryTimeout)
		response, err := resolver(ctx, query)
		cancel()
		if err != nil || len(response) == 0 || len(response) > 65535 {
			return
		}
		packet := make([]byte, 2+len(response))
		binary.BigEndian.PutUint16(packet, uint16(len(response)))
		copy(packet[2:], response)
		if err := writeAll(connection, packet); err != nil {
			return
		}
	}
}

type dnsResponse struct {
	payload []byte
	from    net.Addr
}

// dnsPacketConn 在本机回答 Windows 发来的 UDP DNS 查询。
type dnsPacketConn struct {
	resolveDNS func(context.Context, []byte) ([]byte, error)

	responses chan dnsResponse
	done      chan struct{}
	closeOnce sync.Once

	deadlineMu    sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time
}

func newFakeDNSPacketConn(resolver func([]byte) ([]byte, error)) *dnsPacketConn {
	return newDNSPacketConn(func(_ context.Context, payload []byte) ([]byte, error) {
		return resolver(payload)
	})
}

func newDNSPacketConn(resolver func(context.Context, []byte) ([]byte, error)) *dnsPacketConn {
	return &dnsPacketConn{
		resolveDNS: resolver,
		responses:  make(chan dnsResponse, 1),
		done:       make(chan struct{}),
	}
}

func (c *dnsPacketConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	if len(payload) == 0 || len(payload) > 65535 {
		return 0, errors.New("DNS 查询长度无效")
	}

	deadline := time.Now().Add(dnsQueryTimeout)
	if configured := c.currentWriteDeadline(); !configured.IsZero() && configured.Before(deadline) {
		deadline = configured
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}

	response, err := c.resolveDNS(ctx, payload)
	if err != nil {
		return 0, err
	}
	if address == nil {
		address = &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53}
	}

	select {
	case c.responses <- dnsResponse{payload: response, from: address}:
		return len(payload), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-c.done:
		return 0, net.ErrClosed
	}
}

func (c *dnsPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	deadline := c.currentReadDeadline()
	var timer *time.Timer
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		duration := time.Until(deadline)
		if duration <= 0 {
			return 0, nil, timeoutError{}
		}
		timer = time.NewTimer(duration)
		timeout = timer.C
		defer timer.Stop()
	}

	select {
	case response := <-c.responses:
		return copy(buffer, response.payload), response.from, nil
	case <-timeout:
		return 0, nil, timeoutError{}
	case <-c.done:
		return 0, nil, net.ErrClosed
	}
}

func (c *dnsPacketConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
	})
	return nil
}

func (c *dnsPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

func (c *dnsPacketConn) SetDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = deadline
	c.writeDeadline = deadline
	c.deadlineMu.Unlock()
	return nil
}

func (c *dnsPacketConn) SetReadDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = deadline
	c.deadlineMu.Unlock()
	return nil
}

func (c *dnsPacketConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = deadline
	c.deadlineMu.Unlock()
	return nil
}

func (c *dnsPacketConn) currentReadDeadline() time.Time {
	c.deadlineMu.RLock()
	defer c.deadlineMu.RUnlock()
	return c.readDeadline
}

func (c *dnsPacketConn) currentWriteDeadline() time.Time {
	c.deadlineMu.RLock()
	defer c.deadlineMu.RUnlock()
	return c.writeDeadline
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "DNS 查询超时" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
