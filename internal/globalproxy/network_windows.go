//go:build windows

package globalproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	adapterName       = "SSH VPN"
	tunnelIPv4        = "198.18.0.1"
	tunnelIPv4Mask    = "255.255.255.0"
	tunnelIPv6        = "fd00::1"
	tunnelDNSIPv4     = "198.18.0.2"
	tunnelDNSIPv6     = "fd00::2"
	networkStateFile  = "network-state.json"
	networkCommandTTL = 15 * time.Second
)

var (
	runNetshCommand       = runNetsh
	ipv4RouteExists       = hasIPv4Route
	listDNSServerAddrs    = configuredDNSServers
	flushDNSResolverCache = flushSystemDNSCache
	dnsFlushProcedure     = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")
)

type defaultRoute struct {
	InterfaceName  string
	InterfaceIndex uint32
	Gateway        string
	Metric         uint64
}

type persistedNetworkState struct {
	AdapterName         string   `json:"adapter_name"`
	ServerPrefix        string   `json:"server_prefix"`
	OriginalInterface   string   `json:"original_interface"`
	OriginalGateway     string   `json:"original_gateway"`
	ServerRouteWasAdded bool     `json:"server_route_was_added"`
	DNSPrefixes         []string `json:"dns_prefixes,omitempty"`
}

type networkConfiguration struct {
	state     persistedNetworkState
	statePath string
	logger    *slog.Logger
}

func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func findDefaultIPv4Route() (defaultRoute, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return defaultRoute{}, fmt.Errorf("读取 Windows IPv4 路由表失败：%w", err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))

	var selected defaultRoute
	found := false
	for _, row := range table.Rows() {
		if row.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		prefix, ok := rawIPv4(row.DestinationPrefix.Prefix)
		if !ok || !prefix.Equal(net.IPv4zero) {
			continue
		}
		gateway, ok := rawIPv4(row.NextHop)
		if !ok || gateway.Equal(net.IPv4zero) {
			continue
		}
		iface, err := net.InterfaceByIndex(int(row.InterfaceIndex))
		if err != nil || iface.Flags&net.FlagLoopback != 0 || iface.Name == adapterName {
			continue
		}

		metric := uint64(row.Metric)
		interfaceRow := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceIndex: row.InterfaceIndex}
		if err := windows.GetIpInterfaceEntry(&interfaceRow); err == nil {
			metric += uint64(interfaceRow.Metric)
		}
		if !found || metric < selected.Metric {
			selected = defaultRoute{
				InterfaceName:  iface.Name,
				InterfaceIndex: row.InterfaceIndex,
				Gateway:        gateway.String(),
				Metric:         metric,
			}
			found = true
		}
	}
	if !found {
		return defaultRoute{}, errors.New("找不到可用的 IPv4 默认网关")
	}
	return selected, nil
}

func rawIPv4(address windows.RawSockaddrInet) (net.IP, bool) {
	if address.Family != windows.AF_INET {
		return nil, false
	}
	value := (*windows.RawSockaddrInet4)(unsafe.Pointer(&address))
	return net.IPv4(value.Addr[0], value.Addr[1], value.Addr[2], value.Addr[3]), true
}

func hasIPv4Route(prefix net.IP, prefixLength uint8, interfaceIndex uint32, gateway net.IP) bool {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return false
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))

	for _, row := range table.Rows() {
		if row.InterfaceIndex != interfaceIndex || row.DestinationPrefix.PrefixLength != prefixLength {
			continue
		}
		rowPrefix, prefixOK := rawIPv4(row.DestinationPrefix.Prefix)
		rowGateway, gatewayOK := rawIPv4(row.NextHop)
		if prefixOK && gatewayOK && rowPrefix.Equal(prefix) && rowGateway.Equal(gateway) {
			return true
		}
	}
	return false
}

func configuredDNSServers() ([]net.IP, error) {
	size := uint32(15000)
	for {
		buffer := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("读取 Windows DNS 配置失败：%w", err)
		}

		seen := make(map[string]struct{})
		var servers []net.IP
		for adapter := first; adapter != nil; adapter = adapter.Next {
			if adapter.OperStatus != windows.IfOperStatusUp || windows.UTF16PtrToString(adapter.FriendlyName) == adapterName {
				continue
			}
			for current := adapter.FirstDnsServerAddress; current != nil; current = current.Next {
				address := append(net.IP(nil), current.Address.IP()...)
				if len(address) == 0 || address.IsUnspecified() || address.IsLoopback() {
					continue
				}
				text := address.String()
				if _, exists := seen[text]; exists {
					continue
				}
				seen[text] = struct{}{}
				servers = append(servers, address)
			}
		}
		return servers, nil
	}
}

func configureNetwork(ctx context.Context, route defaultRoute, serverIP net.IP, logger *slog.Logger) (*networkConfiguration, error) {
	serverIPv4 := serverIP.To4()
	if serverIPv4 == nil {
		return nil, errors.New("第一版全局模式要求 SSH 服务器通过 IPv4 连接")
	}
	dnsServers, err := listDNSServerAddrs()
	if err != nil {
		return nil, err
	}
	statePath, err := portableFile(networkStateFile)
	if err != nil {
		return nil, err
	}
	serverRouteExists := ipv4RouteExists(serverIPv4, 32, route.InterfaceIndex, net.ParseIP(route.Gateway))
	dnsPrefixes := make([]string, 0, len(dnsServers))
	for _, address := range dnsServers {
		if address.To4() != nil {
			dnsPrefixes = append(dnsPrefixes, address.String()+"/32")
		} else if address.To16() != nil {
			dnsPrefixes = append(dnsPrefixes, address.String()+"/128")
		}
	}
	configuration := &networkConfiguration{
		state: persistedNetworkState{
			AdapterName:         adapterName,
			ServerPrefix:        serverIPv4.String() + "/32",
			OriginalInterface:   route.InterfaceName,
			OriginalGateway:     route.Gateway,
			ServerRouteWasAdded: !serverRouteExists,
			DNSPrefixes:         dnsPrefixes,
		},
		statePath: statePath,
		logger:    logger,
	}
	if err := configuration.saveState(); err != nil {
		return nil, err
	}

	commands := [][]string{
		{"interface", "ipv4", "set", "address", "name=" + adapterName, "source=static", "address=" + tunnelIPv4, "mask=" + tunnelIPv4Mask, "gateway=none", "store=active"},
		{"interface", "ipv6", "set", "address", "interface=" + adapterName, "address=" + tunnelIPv6, "store=active"},
		{"interface", "ipv4", "set", "dnsservers", "name=" + adapterName, "source=static", "address=" + tunnelDNSIPv4, "register=none", "validate=no"},
		{"interface", "ipv6", "set", "dnsservers", "name=" + adapterName, "source=static", "address=" + tunnelDNSIPv6, "register=none", "validate=no"},
	}
	if !serverRouteExists {
		commands = append(commands, []string{"interface", "ipv4", "add", "route", "prefix=" + configuration.state.ServerPrefix, "interface=" + route.InterfaceName, "nexthop=" + route.Gateway, "metric=1", "store=active"})
	}
	for _, prefix := range configuration.state.DNSPrefixes {
		if strings.Contains(prefix, ":") {
			commands = append(commands, []string{"interface", "ipv6", "add", "route", "prefix=" + prefix, "interface=" + adapterName, "nexthop=" + tunnelIPv6, "metric=1", "store=active"})
		} else {
			commands = append(commands, []string{"interface", "ipv4", "add", "route", "prefix=" + prefix, "interface=" + adapterName, "nexthop=" + tunnelIPv4, "metric=1", "store=active"})
		}
	}
	commands = append(commands,
		[]string{"interface", "ipv4", "add", "route", "prefix=0.0.0.0/1", "interface=" + adapterName, "nexthop=" + tunnelIPv4, "metric=1", "store=active"},
		[]string{"interface", "ipv4", "add", "route", "prefix=128.0.0.0/1", "interface=" + adapterName, "nexthop=" + tunnelIPv4, "metric=1", "store=active"},
		[]string{"interface", "ipv6", "add", "route", "prefix=::/1", "interface=" + adapterName, "nexthop=" + tunnelIPv6, "metric=1", "store=active"},
		[]string{"interface", "ipv6", "add", "route", "prefix=8000::/1", "interface=" + adapterName, "nexthop=" + tunnelIPv6, "metric=1", "store=active"},
	)

	for _, arguments := range commands {
		if err := runNetshCommand(ctx, arguments...); err != nil {
			configuration.cleanup(context.Background())
			return nil, fmt.Errorf("配置 Windows 全局路由失败：%w", err)
		}
	}
	if err := flushDNSResolverCache(); err != nil {
		configuration.cleanup(context.Background())
		return nil, err
	}
	return configuration, nil
}

func flushSystemDNSCache() error {
	result, _, callErr := dnsFlushProcedure.Call()
	if result != 0 {
		return nil
	}
	if errno, ok := callErr.(syscall.Errno); ok && errno != 0 {
		return fmt.Errorf("清空 Windows DNS 缓存失败：%w", errno)
	}
	return errors.New("清空 Windows DNS 缓存失败")
}

func (c *networkConfiguration) saveState() error {
	data, err := json.MarshalIndent(c.state, "", "  ")
	if err != nil {
		return fmt.Errorf("生成网络恢复状态失败：%w", err)
	}
	temporaryPath := c.statePath + ".tmp"
	if err := os.WriteFile(temporaryPath, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("保存网络恢复状态失败：%w", err)
	}
	if err := os.Rename(temporaryPath, c.statePath); err != nil {
		os.Remove(temporaryPath)
		return fmt.Errorf("更新网络恢复状态失败：%w", err)
	}
	return nil
}

func (c *networkConfiguration) Close() error {
	c.cleanup(context.Background())
	if err := os.Remove(c.statePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("删除网络恢复状态失败：%w", err)
	}
	return nil
}

func (c *networkConfiguration) cleanup(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, networkCommandTTL)
	defer cancel()
	cleanupNetworkState(ctx, c.state, c.logger)
}

func cleanupNetworkState(ctx context.Context, state persistedNetworkState, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	commands := [][]string{
		{"interface", "ipv6", "delete", "route", "prefix=8000::/1", "interface=" + state.AdapterName, "nexthop=" + tunnelIPv6, "store=active"},
		{"interface", "ipv6", "delete", "route", "prefix=::/1", "interface=" + state.AdapterName, "nexthop=" + tunnelIPv6, "store=active"},
		{"interface", "ipv4", "delete", "route", "prefix=128.0.0.0/1", "interface=" + state.AdapterName, "nexthop=" + tunnelIPv4, "store=active"},
		{"interface", "ipv4", "delete", "route", "prefix=0.0.0.0/1", "interface=" + state.AdapterName, "nexthop=" + tunnelIPv4, "store=active"},
	}
	if state.ServerRouteWasAdded && state.ServerPrefix != "" && state.OriginalInterface != "" && state.OriginalGateway != "" {
		commands = append(commands, []string{"interface", "ipv4", "delete", "route", "prefix=" + state.ServerPrefix, "interface=" + state.OriginalInterface, "nexthop=" + state.OriginalGateway, "store=active"})
	}
	for _, prefix := range state.DNSPrefixes {
		if strings.Contains(prefix, ":") {
			commands = append(commands, []string{"interface", "ipv6", "delete", "route", "prefix=" + prefix, "interface=" + state.AdapterName, "nexthop=" + tunnelIPv6, "store=active"})
		} else {
			commands = append(commands, []string{"interface", "ipv4", "delete", "route", "prefix=" + prefix, "interface=" + state.AdapterName, "nexthop=" + tunnelIPv4, "store=active"})
		}
	}
	commands = append(commands,
		[]string{"interface", "ipv6", "delete", "dnsservers", "name=" + state.AdapterName, "address=all", "validate=no"},
		[]string{"interface", "ipv4", "delete", "dnsservers", "name=" + state.AdapterName, "address=all", "validate=no"},
		[]string{"interface", "ipv6", "delete", "address", "interface=" + state.AdapterName, "address=" + tunnelIPv6, "store=active"},
		[]string{"interface", "ipv4", "delete", "address", "name=" + state.AdapterName, "address=" + tunnelIPv4, "store=active"},
	)
	for _, arguments := range commands {
		if err := runNetshCommand(ctx, arguments...); err != nil {
			logger.Debug("清理不存在或已经移除的临时网络项", "错误", err)
		}
	}
	if err := flushDNSResolverCache(); err != nil {
		logger.Warn("清理全局模式 DNS 缓存失败", "错误", err)
	}
}

// Recover 清理上次异常退出遗留的路由。状态文件只由程序生成，不需要用户维护。
func Recover(logger *slog.Logger) error {
	if !isElevated() {
		return errors.New("启用全局模式需要管理员权限，请以管理员身份启动 SSH VPN")
	}
	statePath, err := portableFile(networkStateFile)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(statePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("读取上次网络恢复状态失败：%w", err)
	}
	var state persistedNetworkState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("解析上次网络恢复状态失败：%w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), networkCommandTTL)
	cleanupNetworkState(ctx, state, logger)
	cancel()
	if err := os.Remove(statePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("删除旧网络恢复状态失败：%w", err)
	}
	if logger != nil {
		logger.Info("已恢复上次异常退出遗留的临时网络设置")
	}
	return nil
}

func runNetsh(ctx context.Context, arguments ...string) error {
	command := exec.CommandContext(ctx, "netsh.exe", arguments...)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := command.CombinedOutput()
	if err == nil {
		return nil
	}
	detail := err.Error()
	if utf8.Valid(output) {
		if text := strings.TrimSpace(string(output)); text != "" {
			detail = text
		}
	}
	return fmt.Errorf("netsh %s：%s", strings.Join(arguments, " "), detail)
}
