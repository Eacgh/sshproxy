//go:build windows

package globalproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/bits"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/windows"
)

const (
	ipUnicastIf           = 31
	ipv6UnicastIf         = 31
	directTCPDialTimeout  = 15 * time.Second
	directDNSTimeout      = 3 * time.Second
	directDNSMinTTL       = 30 * time.Second
	directDNSMaxTTL       = 300 * time.Second
)

var fallbackDirectDNS = []netip.Addr{
	netip.MustParseAddr("223.5.5.5"),
	netip.MustParseAddr("119.29.29.29"),
}

type directDNSCacheEntry struct {
	addr      netip.Addr
	expiresAt time.Time
}

type windowsDirectDialer struct {
	ipv4Index  uint32
	ipv6Index  uint32
	dnsServers []string
	logger     *slog.Logger
	control    func(string, string, syscall.RawConn) error

	queryID atomic.Uint32
	mu      sync.Mutex
	cache   map[string]directDNSCacheEntry
}

func newWindowsDirectDialer(ipv4Index, ipv6Index uint32, dnsAddrs []netip.Addr, logger *slog.Logger) *windowsDirectDialer {
	if logger == nil {
		logger = slog.Default()
	}
	if len(dnsAddrs) == 0 {
		dnsAddrs = fallbackDirectDNS
	}
	servers := make([]string, 0, len(dnsAddrs))
	for _, addr := range dnsAddrs {
		addr = addr.Unmap()
		if addr.Is4() {
			servers = append(servers, net.JoinHostPort(addr.String(), "53"))
		}
	}
	if len(servers) == 0 {
		for _, addr := range fallbackDirectDNS {
			servers = append(servers, net.JoinHostPort(addr.String(), "53"))
		}
	}
	return &windowsDirectDialer{
		ipv4Index:  ipv4Index,
		ipv6Index:  ipv6Index,
		dnsServers: servers,
		logger:     logger,
		control:    bindInterfaceControl(ipv4Index, ipv6Index),
		cache:      make(map[string]directDNSCacheEntry),
	}
}

func bindInterfaceControl(ipv4Index, ipv6Index uint32) func(string, string, syscall.RawConn) error {
	return func(network, _ string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			handle := windows.Handle(fd)
			switch network {
			case "tcp4", "udp4":
				if ipv4Index != 0 {
					// Windows IP_UNICAST_IF 要求大端（网络字节序）接口索引。
					if err := windows.SetsockoptInt(handle, windows.IPPROTO_IP, ipUnicastIf, int(bits.ReverseBytes32(ipv4Index))); err != nil {
						sockErr = fmt.Errorf("绑定 IPv4 物理出站网卡失败：%w", err)
					}
				}
			case "tcp6", "udp6":
				if ipv6Index != 0 {
					// Windows IPV6_UNICAST_IF 要求主机字节序接口索引。
					if err := windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, ipv6UnicastIf, int(ipv6Index)); err != nil {
						sockErr = fmt.Errorf("绑定 IPv6 物理出站网卡失败：%w", err)
					}
				}
			}
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}

func (d *windowsDirectDialer) DialTCP(ctx context.Context, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip, parseErr := netip.ParseAddr(strings.Trim(host, "[]"))
	if parseErr != nil {
		resolved, err := d.ResolveIPv4(ctx, host)
		if err != nil {
			return nil, err
		}
		ip = resolved
	}
	ip = ip.Unmap()
	network := "tcp4"
	if ip.Is6() {
		network = "tcp6"
	}
	dialer := net.Dialer{Timeout: directTCPDialTimeout}
	if !ip.IsLoopback() {
		dialer.Control = d.control
	}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
}

func (d *windowsDirectDialer) ListenUDP(ipv6 bool) (net.PacketConn, error) {
	network, bindAddr := "udp4", "0.0.0.0:0"
	if ipv6 {
		network, bindAddr = "udp6", "[::]:0"
	}
	lc := net.ListenConfig{Control: d.control}
	return lc.ListenPacket(context.Background(), network, bindAddr)
}

func (d *windowsDirectDialer) ResolveIPv4(ctx context.Context, host string) (netip.Addr, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if name == "" {
		return netip.Addr{}, errors.New("直连 DNS 解析的域名不能为空")
	}
	if ip, err := netip.ParseAddr(strings.Trim(name, "[]")); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			return ip, nil
		}
		return netip.Addr{}, errors.New("直连 DNS 解析仅支持返回 IPv4 地址")
	}

	now := time.Now()
	d.mu.Lock()
	if entry, ok := d.cache[name]; ok && now.Before(entry.expiresAt) {
		d.mu.Unlock()
		return entry.addr, nil
	}
	d.mu.Unlock()

	dnsName, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return netip.Addr{}, fmt.Errorf("无效域名 %q：%w", name, err)
	}
	queryID := uint16(d.queryID.Add(1))
	queryMsg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               queryID,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{{
			Name:  dnsName,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	queryBytes, err := queryMsg.Pack()
	if err != nil {
		return netip.Addr{}, err
	}

	var lastErr error
	for _, server := range d.dnsServers {
		addr, ttl, err := d.queryServer(ctx, server, queryID, queryBytes)
		if err != nil {
			lastErr = err
			continue
		}
		d.mu.Lock()
		d.cache[name] = directDNSCacheEntry{
			addr:      addr,
			expiresAt: time.Now().Add(ttl),
		}
		d.mu.Unlock()
		return addr, nil
	}
	if lastErr != nil {
		return netip.Addr{}, fmt.Errorf("物理网卡直连解析域名 %s 失败：%w", name, lastErr)
	}
	return netip.Addr{}, fmt.Errorf("物理网卡直连解析域名 %s 失败", name)
}

func (d *windowsDirectDialer) queryServer(ctx context.Context, server string, queryID uint16, query []byte) (netip.Addr, time.Duration, error) {
	queryCtx, cancel := context.WithTimeout(ctx, directDNSTimeout)
	defer cancel()

	host, _, _ := net.SplitHostPort(server)
	srvIP, _ := netip.ParseAddr(strings.Trim(host, "[]"))
	dialer := net.Dialer{Timeout: directDNSTimeout}
	if !srvIP.IsLoopback() {
		dialer.Control = d.control
	}

	conn, err := dialer.DialContext(queryCtx, "udp4", server)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	deadline, _ := queryCtx.Deadline()
	_ = conn.SetDeadline(deadline)
	_, writeErr := conn.Write(query)
	var response []byte
	if writeErr == nil {
		buf := make([]byte, 1500)
		n, readErr := conn.Read(buf)
		if readErr == nil {
			response = buf[:n]
		} else {
			err = readErr
		}
	} else {
		err = writeErr
	}
	_ = conn.Close()

	var msg dnsmessage.Message
	needTCP := err != nil || len(response) == 0
	if !needTCP {
		if unpackErr := msg.Unpack(response); unpackErr != nil || msg.Header.ID != queryID || !msg.Header.Response {
			needTCP = true
		} else if msg.Header.Truncated {
			needTCP = true
		}
	}
	if needTCP {
		tcpResp, tcpErr := d.queryServerTCP(queryCtx, dialer, server, query)
		if tcpErr != nil {
			if err != nil {
				return netip.Addr{}, 0, err
			}
			return netip.Addr{}, 0, tcpErr
		}
		if unpackErr := msg.Unpack(tcpResp); unpackErr != nil {
			return netip.Addr{}, 0, unpackErr
		}
		if msg.Header.ID != queryID || !msg.Header.Response {
			return netip.Addr{}, 0, errors.New("DNS 服务器返回了不匹配的 TCP 响应")
		}
	}

	if msg.Header.RCode != dnsmessage.RCodeSuccess {
		return netip.Addr{}, 0, fmt.Errorf("DNS 查询返回错误状态 %s", strconv.Itoa(int(msg.Header.RCode)))
	}
	for _, answer := range msg.Answers {
		if a, ok := answer.Body.(*dnsmessage.AResource); ok {
			ttl := time.Duration(answer.Header.TTL) * time.Second
			if ttl < directDNSMinTTL {
				ttl = directDNSMinTTL
			}
			if ttl > directDNSMaxTTL {
				ttl = directDNSMaxTTL
			}
			return netip.AddrFrom4(a.A), ttl, nil
		}
	}
	return netip.Addr{}, 0, errors.New("DNS 响应中没有 IPv4 记录")
}

func (d *windowsDirectDialer) queryServerTCP(ctx context.Context, dialer net.Dialer, server string, query []byte) ([]byte, error) {
	conn, err := dialer.DialContext(ctx, "tcp4", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	packet := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(packet[:2], uint16(len(query)))
	copy(packet[2:], query)
	if err := writeAll(conn, packet); err != nil {
		return nil, err
	}
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(hdr[:]))
	if length == 0 {
		return nil, errors.New("DNS TCP 响应为空")
	}
	resp := make([]byte, length)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}
