//go:build windows

package globalproxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestBindInterfaceControlSetsUnicastIFOption(t *testing.T) {
	route, err := findDefaultIPv4Route()
	if err != nil {
		t.Skipf("当前环境没有可用的 IPv4 默认网关，跳过网卡绑定测试：%v", err)
	}
	lc := net.ListenConfig{
		Control: bindInterfaceControl(route.InterfaceIndex, 0),
	}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("在物理网卡索引 %d 上绑定 IP_UNICAST_IF 失败：%v", route.InterfaceIndex, err)
	}
	_ = pc.Close()
}

func TestWindowsDirectDialerResolveIPv4WithLocalMockDNS(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if err := q.Unpack(buf[:n]); err != nil || len(q.Questions) == 0 {
				continue
			}
			resp := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:                 q.Header.ID,
					Response:           true,
					RecursionAvailable: true,
				},
				Questions: q.Questions,
				Answers: []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{
						Name:  q.Questions[0].Name,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
						TTL:   120,
					},
					Body: &dnsmessage.AResource{A: [4]byte{110, 242, 68, 66}},
				}},
			}
			packed, err := resp.Pack()
			if err == nil {
				_, _ = pc.WriteTo(packed, addr)
			}
		}
	}()

	dialer := &windowsDirectDialer{
		dnsServers: []string{pc.LocalAddr().String()},
		logger:     slog.Default(),
		control:    bindInterfaceControl(0, 0),
		cache:      make(map[string]directDNSCacheEntry),
	}

	resolved, err := dialer.ResolveIPv4(context.Background(), "www.baidu.com")
	if err != nil {
		t.Fatalf("ResolveIPv4() 失败：%v", err)
	}
	if resolved != netip.MustParseAddr("110.242.68.66") {
		t.Fatalf("ResolveIPv4() = %s，期望 110.242.68.66", resolved)
	}
}

func TestWindowsDirectDialerRejectsIPv6WithoutPhysicalIndexAndTracksUDPPorts(t *testing.T) {
	dialer := newWindowsDirectDialer(0, 0, nil, slog.Default())
	if _, err := dialer.ListenUDP(true); !errors.Is(err, errNoDirectIPv6) {
		t.Fatalf("无 IPv6 物理网卡时 ListenUDP(true) 返回 %v，期望 errNoDirectIPv6", err)
	}
	if _, err := dialer.DialTCP(context.Background(), "[2408:8726:2000:6::132]:443"); !errors.Is(err, errNoDirectIPv6) {
		t.Fatalf("无 IPv6 物理网卡时 IPv6 DialTCP 返回 %v，期望 errNoDirectIPv6", err)
	}

	route, err := findDefaultIPv4Route()
	if err != nil {
		t.Skipf("当前环境没有可用的 IPv4 默认网关，跳过端口跟踪测试：%v", err)
	}
	v4Dialer := newWindowsDirectDialer(route.InterfaceIndex, 0, nil, slog.Default())
	pc, err := v4Dialer.ListenUDP(false)
	if err != nil {
		t.Fatalf("ListenUDP(false) 失败：%v", err)
	}
	udpAddr, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok || udpAddr.Port == 0 {
		_ = pc.Close()
		t.Fatalf("ListenUDP(false) 返回异常本地地址：%v", pc.LocalAddr())
	}
	port := uint16(udpAddr.Port)
	if !v4Dialer.OwnsLocalUDPPort(false, port) {
		_ = pc.Close()
		t.Fatalf("ListenUDP 打开后 OwnsLocalUDPPort(false, %d) 应为 true", port)
	}
	_ = pc.Close()
	if v4Dialer.OwnsLocalUDPPort(false, port) {
		t.Fatalf("Close() 后 OwnsLocalUDPPort(false, %d) 应清除为 false", port)
	}
}
