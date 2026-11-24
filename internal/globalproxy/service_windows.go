//go:build windows

package globalproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"runtime"
	"runtime/debug"
	"sync"

	"github.com/xjasonlyu/tun2socks/v2/core"
	tundevice "github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	"github.com/xjasonlyu/tun2socks/v2/core/option"
	tunlog "github.com/xjasonlyu/tun2socks/v2/log"
	"golang.org/x/sys/windows"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"sshvpn/internal/config"
)

const (
	tunnelMTU = 1500
)

var adapterGUID = windows.GUID{Data1: 0x6dcd3f96, Data2: 0x1df3, Data3: 0x4eec, Data4: [8]byte{0xb7, 0x86, 0x62, 0x89, 0x96, 0xe5, 0x31, 0x12}}

type windowsController struct {
	options Options

	mu        sync.Mutex
	started   bool
	closed    bool
	network   *networkConfiguration
	device    tundevice.Device
	stack     *stack.Stack
	transport *fastTransportHandler
}

// New 创建 Windows 全局代理控制器，但不会在构造阶段修改系统网络。
func New(options Options) Controller {
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	return &windowsController{options: options}
}

func (c *windowsController) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started {
		return nil
	}
	if c.closed {
		return netClosedError{}
	}
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("当前内嵌的 Wintun 只支持 x64，当前架构为 %s", runtime.GOARCH)
	}
	if !isElevated() {
		return errors.New("启用全局模式需要管理员权限，请以管理员身份启动 SSH VPN")
	}
	if c.options.Dialer == nil {
		return errors.New("全局模式缺少 SSH 转发器")
	}
	if c.options.SSHServerIP.To4() == nil {
		return errors.New("第一版全局模式要求 SSH 服务器通过 IPv4 连接")
	}
	if _, err := ensureWintunDLL(); err != nil {
		return err
	}
	route, err := findDefaultIPv4Route()
	if err != nil {
		return err
	}
	ipv6InterfaceIndex := findDefaultIPv6InterfaceIndex()
	physicalDNS, err := physicalIPv4DNSServers(route.InterfaceIndex)
	if err != nil {
		c.options.Logger.Warn("读取物理网卡 DNS 失败，将使用公共直连 DNS", "错误", err)
	}
	mode := c.options.Mode
	if mode == "" {
		mode = config.ModeGlobal
	}

	// Wintun 自带英文驱动安装日志；界面使用下面的中文生命周期日志代替。
	log.SetOutput(io.Discard)
	silentLogger, _ := tunlog.NewLeveled(tunlog.SilentLevel)
	tunlog.SetLogger(silentLogger)
	wgtun.WintunTunnelType = "SshVpn"
	wgtun.WintunStaticRequestedGUID = &adapterGUID
	device, err := tun.Open(adapterName, tunnelMTU)
	if err != nil {
		return fmt.Errorf("创建 Wintun 虚拟网卡失败：%w", err)
	}

	directDialer := newWindowsDirectDialer(route.InterfaceIndex, ipv6InterfaceIndex, physicalDNS, c.options.Logger)
	transport := newFastTransportHandlerWithConfig(fastTransportConfig{
		dialer:       c.options.Dialer,
		dnsServer:    c.options.DNSServer,
		logger:       c.options.Logger,
		traffic:      c.options.Traffic,
		mode:         mode,
		processRules: c.options.ProcessRules,
		lookup:       newWindowsProcessLookup(),
		direct:       directDialer,
	})
	networkStack, err := core.CreateStack(&core.Config{
		LinkEndpoint:     device,
		TransportHandler: transport,
		// 使用 tun2socks 官方默认栈配置（reno 拥塞控制、关闭 Nagle、开启 SACK），
		// 并收紧每条连接 TCP 收发默认/上限缓冲（默认 256 KiB、上限 1 MiB），
		// 避免海量并发连接时 gVisor 缓冲区长期占用数 GB 堆内存。
		Options: []option.Option{
			option.WithDefault(),
			option.WithTCPSendBufferSizeRange(4<<10, 256<<10, 1<<20),
			option.WithTCPReceiveBufferSizeRange(4<<10, 256<<10, 1<<20),
		},
	})
	if err != nil {
		transport.Close()
		device.Close()
		return fmt.Errorf("启动用户态 TCP/IP 网络栈失败：%w", err)
	}

	network, err := configureNetwork(ctx, route, c.options.SSHServerIP, c.options.Logger)
	if err != nil {
		device.Close()
		networkStack.Close()
		networkStack.Wait()
		transport.Close()
		return err
	}

	c.device = device
	c.stack = networkStack
	c.transport = transport
	c.network = network
	c.started = true
	dnsMode := "本地 Fake-IP，由 SSH 服务器解析"
	if c.options.DNSServer != "" {
		dnsMode = "经 SSH 查询 " + c.options.DNSServer + "，Fake-IP 使用 IPv4"
	}
	if mode == config.ModeProcess {
		c.options.Logger.Info(
			"按进程分流代理已启用（Wintun + gVisor）",
			"虚拟网卡", adapterName,
			"出站物理网卡", route.InterfaceName,
			"已启用规则数", countEnabledRules(c.options.ProcessRules),
			"域名解析", dnsMode,
		)
	} else {
		c.options.Logger.Info(
			"全局 TCP 代理已启用",
			"虚拟网卡", adapterName,
			"MTU", tunnelMTU,
			"TCP缓冲", "系统默认",
			"中继缓冲", "32 KiB",
			"域名解析", dnsMode,
			"建连保护", "同目标限流和超时熔断",
		)
		c.options.Logger.Warn("当前版本会阻止普通 UDP；浏览器会回退到 TCP，游戏和语音软件可能不可用")
	}
	return nil
}

func (c *windowsController) UpdateProcessRules(rules []config.ProcessRule) int {
	c.mu.Lock()
	transport := c.transport
	mode := c.options.Mode
	if mode == "" {
		mode = config.ModeGlobal
	}
	c.options.ProcessRules = append([]config.ProcessRule(nil), rules...)
	c.mu.Unlock()
	if transport == nil {
		return 0
	}
	closed := transport.SetProcessRules(rules)
	if mode == config.ModeProcess {
		c.options.Logger.Info(
			"已热更新进程分流规则",
			"已启用规则数", countEnabledRules(rules),
			"已断开受影响连接", closed,
		)
	}
	return closed
}

func countEnabledRules(rules []config.ProcessRule) int {
	count := 0
	for _, rule := range rules {
		if rule.IsEnabled() && rule.MatchTarget() != "" {
			count++
		}
	}
	return count
}

func (c *windowsController) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if !c.started {
		return nil
	}

	var errs []error
	// 先关闭设备（结束 Wintun 会话），再清理网络：删除虚拟网卡前必须
	// 确保没有活动会话，否则 netsh 删除接口会失败并留下残余网卡。
	if c.device != nil {
		c.device.Close()
	}
	if c.network != nil {
		if err := c.network.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.transport != nil {
		c.transport.Close()
	}
	if c.stack != nil {
		c.stack.Close()
		c.stack.Wait()
	}
	debug.FreeOSMemory()
	c.options.Logger.Info("全局 TCP 代理已停止，临时路由已经清理")
	return errors.Join(errs...)
}

type netClosedError struct{}

func (netClosedError) Error() string { return "全局代理控制器已经关闭" }
