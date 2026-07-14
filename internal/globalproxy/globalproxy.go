// Package globalproxy 把系统 IP 流量交给现有 SSH 连接处理。
// Windows 实现使用 Wintun 和用户态网络栈；其他平台只保留可编译的占位实现。
package globalproxy

import (
	"context"
	"log/slog"
	"net"
)

// Dialer 是全局转发层访问 SSH direct-tcpip 的最小接口。
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Controller 管理虚拟网卡、临时路由和用户态网络栈的生命周期。
type Controller interface {
	Start(ctx context.Context) error
	Close() error
}

// Options 汇总启动全局模式所需的内部对象和已校验设置。
type Options struct {
	SSHServerIP net.IP
	Dialer      Dialer
	DNSServer   string
	Logger      *slog.Logger
}
