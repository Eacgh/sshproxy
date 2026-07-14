//go:build windows

package globalproxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigureNetworkAddsAndRemovesManagedRoutes(t *testing.T) {
	directory := t.TempDir()
	previousPortableFile := portableFile
	previousRunner := runNetshCommand
	previousRouteExists := ipv4RouteExists
	previousDNSServers := listDNSServerAddrs
	previousDNSFlush := flushDNSResolverCache
	portableFile = func(name string) (string, error) { return filepath.Join(directory, name), nil }
	ipv4RouteExists = func(net.IP, uint8, uint32, net.IP) bool { return false }
	listDNSServerAddrs = func() ([]net.IP, error) { return []net.IP{net.IPv4(192, 168, 1, 1)}, nil }
	flushDNSResolverCache = func() error { return nil }
	var commands []string
	runNetshCommand = func(_ context.Context, arguments ...string) error {
		commands = append(commands, strings.Join(arguments, " "))
		return nil
	}
	t.Cleanup(func() {
		portableFile = previousPortableFile
		runNetshCommand = previousRunner
		ipv4RouteExists = previousRouteExists
		listDNSServerAddrs = previousDNSServers
		flushDNSResolverCache = previousDNSFlush
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	configuration, err := configureNetwork(context.Background(), defaultRoute{
		InterfaceName:  "以太网",
		InterfaceIndex: 7,
		Gateway:        "192.168.1.1",
	}, net.IPv4(203, 0, 113, 9), logger)
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 10 {
		t.Fatalf("启动命令数量为 %d：%v", len(commands), commands)
	}
	assertCommandContains(t, commands, "prefix=203.0.113.9/32 interface=以太网 nexthop=192.168.1.1")
	assertCommandContains(t, commands, "prefix=0.0.0.0/1 interface=SSH VPN")
	assertCommandContains(t, commands, "prefix=8000::/1 interface=SSH VPN")
	assertCommandContains(t, commands, "prefix=192.168.1.1/32 interface=SSH VPN")
	assertCommandContains(t, commands, "dnsservers name=SSH VPN source=static address="+tunnelDNSIPv4)
	assertCommandContains(t, commands, "dnsservers name=SSH VPN source=static address="+tunnelDNSIPv6)

	if err := configuration.Close(); err != nil {
		t.Fatal(err)
	}
	assertCommandContains(t, commands, "delete route prefix=203.0.113.9/32")
	assertCommandContains(t, commands, "delete route prefix=0.0.0.0/1")
	assertCommandContains(t, commands, "delete route prefix=192.168.1.1/32")
	assertCommandContains(t, commands, "delete dnsservers name=SSH VPN address=all")
	assertCommandContains(t, commands, "delete address interface=SSH VPN address=fd00::1")
}

func TestConfiguredDNSServersReadsWindowsAdapters(t *testing.T) {
	if _, err := configuredDNSServers(); err != nil {
		t.Fatal(err)
	}
}

func assertCommandContains(t *testing.T, commands []string, expected string) {
	t.Helper()
	for _, command := range commands {
		if strings.Contains(command, expected) {
			return
		}
	}
	t.Fatalf("没有找到命令片段 %q：%v", expected, commands)
}
