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
	"sync"

	"github.com/xjasonlyu/tun2socks/v2/core"
	tundevice "github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	"github.com/xjasonlyu/tun2socks/v2/core/option"
	tunlog "github.com/xjasonlyu/tun2socks/v2/log"
	"golang.org/x/sys/windows"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	tunnelMTU     = 1500
	tcpBufferSize = 4 << 20
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

	transport := newFastTransportHandler(c.options.Dialer, c.options.DNSServer, c.options.Logger)
	networkStack, err := core.CreateStack(&core.Config{
		LinkEndpoint:     device,
		TransportHandler: transport,
		Options: []option.Option{
			option.WithTCPModerateReceiveBuffer(false),
			option.WithTCPSendBufferSize(tcpBufferSize),
			option.WithTCPReceiveBufferSize(tcpBufferSize),
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
	c.options.Logger.Info(
		"全局 TCP 代理已启用",
		"虚拟网卡", adapterName,
		"MTU", tunnelMTU,
		"TCP缓冲", "4 MiB",
		"中继缓冲", "128 KiB",
		"域名解析", dnsMode,
		"建连保护", "同目标限流和超时熔断",
	)
	c.options.Logger.Warn("当前版本会阻止普通 UDP；浏览器会回退到 TCP，游戏和语音软件可能不可用")
	return nil
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
	if c.network != nil {
		if err := c.network.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.device != nil {
		c.device.Close()
	}
	if c.transport != nil {
		c.transport.Close()
	}
	if c.stack != nil {
		c.stack.Close()
		c.stack.Wait()
	}
	c.options.Logger.Info("全局 TCP 代理已停止，临时路由已经清理")
	return errors.Join(errs...)
}

type netClosedError struct{}

func (netClosedError) Error() string { return "全局代理控制器已经关闭" }
