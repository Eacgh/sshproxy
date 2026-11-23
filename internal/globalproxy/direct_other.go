//go:build !windows

package globalproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

type noopDirectDialer struct{}

func (noopDirectDialer) DialTCP(context.Context, string) (net.Conn, error) {
	return nil, errors.New("非 Windows 平台不支持物理网卡直连旁路")
}

func (noopDirectDialer) ListenUDP(bool) (net.PacketConn, error) {
	return nil, errors.New("非 Windows 平台不支持物理网卡直连 UDP")
}

func (noopDirectDialer) ResolveIPv4(context.Context, string) (netip.Addr, error) {
	return netip.Addr{}, errors.New("非 Windows 平台不支持物理网卡直连 DNS")
}
