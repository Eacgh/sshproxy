package sshclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"sshvpn/internal/config"
	"sshvpn/internal/portable"
)

var (
	dataDirectory = portable.Directory
	knownHostsMu  sync.Mutex
)

// SSH 协议没有取消单个 direct-tcpip 开通请求的机制。这里限制真正仍在等待
// 服务端响应的请求数量，避免大量不可达目标耗尽协程和 SSH 多路复用资源。
const (
	maxPendingSSHDials       = 24
	maxPendingSSHToOneTarget = 1
)

type targetDialState struct {
	slots chan struct{}
	users int
}

// Manager 维护一个可复用的 SSH 连接，并在连接失效后按需重建。
type Manager struct {
	cfg       config.Config
	sshConfig *ssh.ClientConfig
	logger    *slog.Logger

	mu        sync.RWMutex
	connectMu sync.Mutex
	client    *ssh.Client
	raw       net.Conn
	dialAddr  string
	serverIP  net.IP
	closed    bool
	done      chan struct{}
	dialSlots chan struct{}
	dialMu    sync.Mutex
	targets   map[string]*targetDialState
	wg        sync.WaitGroup
}

// NewManager 准备密码认证和程序自动管理的主机密钥校验器。
func NewManager(cfg config.Config, logger *slog.Logger) (*Manager, error) {
	if logger == nil {
		logger = slog.Default()
	}
	sshConfig, err := buildClientConfig(cfg, logger)
	if err != nil {
		return nil, err
	}
	return &Manager{
		cfg:       cfg,
		sshConfig: sshConfig,
		logger:    logger,
		done:      make(chan struct{}),
		dialSlots: make(chan struct{}, maxPendingSSHDials),
		targets:   make(map[string]*targetDialState),
	}, nil
}

func buildClientConfig(cfg config.Config, logger *slog.Logger) (*ssh.ClientConfig, error) {
	hostKeyCallback, err := buildHostKeyCallback(logger)
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{
		User:            cfg.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(cfg.Password)},
		HostKeyCallback: hostKeyCallback,
	}, nil
}

// buildHostKeyCallback 使用首次信任机制自动维护应用自己的 known_hosts 文件。
func buildHostKeyCallback(logger *slog.Logger) (ssh.HostKeyCallback, error) {
	baseDir, err := dataDirectory()
	if err != nil {
		return nil, fmt.Errorf("确定便携数据目录失败：%w", err)
	}
	knownHostsPath := filepath.Join(baseDir, "known_hosts")
	file, err := os.OpenFile(knownHostsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("创建 SSH 主机密钥数据库失败：%w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("初始化 SSH 主机密钥数据库失败：%w", err)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		knownHostsMu.Lock()
		defer knownHostsMu.Unlock()

		// 每次握手重新加载，确保首次记录的密钥在自动重连时立即生效。
		verify, err := knownhosts.New(knownHostsPath)
		if err != nil {
			return fmt.Errorf("读取 SSH 主机密钥数据库失败：%w", err)
		}
		if err := verify(hostname, remote, key); err == nil {
			return nil
		} else {
			var keyError *knownhosts.KeyError
			if !errors.As(err, &keyError) {
				return fmt.Errorf("校验 SSH 服务器主机密钥失败：%w", err)
			}
			if len(keyError.Want) > 0 {
				return fmt.Errorf("SSH 服务器 %s 的主机密钥发生变化，已拒绝连接；请确认服务器安全状态后删除 %q 再重试", hostname, knownHostsPath)
			}
		}

		line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)
		file, err := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("保存 SSH 主机密钥失败：%w", err)
		}
		if _, err := io.WriteString(file, line+"\n"); err != nil {
			file.Close()
			return fmt.Errorf("保存 SSH 主机密钥失败：%w", err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("保存 SSH 主机密钥失败：%w", err)
		}
		logger.Info("首次连接，已自动记录 SSH 服务器主机密钥", "地址", hostname, "指纹", ssh.FingerprintSHA256(key))
		return nil
	}, nil
}

// Connect 立即建立 SSH 连接，启动时可借此尽早发现配置或网络问题。
func (m *Manager) Connect(ctx context.Context) error {
	_, err := m.ensureConnected(ctx)
	return err
}

func (m *Manager) ensureConnected(ctx context.Context) (*ssh.Client, error) {
	if client := m.currentClient(); client != nil {
		return client, nil
	}

	// 多个 SOCKS5 请求同时到来时，只允许其中一个执行重连。
	m.connectMu.Lock()
	defer m.connectMu.Unlock()
	if client := m.currentClient(); client != nil {
		return client, nil
	}
	m.mu.RLock()
	closed := m.closed
	m.mu.RUnlock()
	if closed {
		return nil, net.ErrClosed
	}

	address := m.cfg.SSHAddress()
	dialAddress := m.cachedDialAddress(address)
	m.logger.Info("正在连接 SSH 服务器", "地址", address, "用户", m.cfg.Username)
	dialer := net.Dialer{Timeout: m.cfg.ConnectTimeout()}
	raw, err := dialer.DialContext(ctx, "tcp", dialAddress)
	if err != nil {
		return nil, fmt.Errorf("连接 SSH 服务器失败：%w", err)
	}
	// TCP 连接建立后仍要限制 SSH 握手时间，防止服务端无响应时永久等待。
	if err := raw.SetDeadline(time.Now().Add(m.cfg.ConnectTimeout())); err != nil {
		raw.Close()
		return nil, fmt.Errorf("设置 SSH 握手超时失败：%w", err)
	}
	conn, channels, requests, err := ssh.NewClientConn(raw, address, m.sshConfig)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("SSH 握手失败：%w", err)
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		raw.Close()
		return nil, fmt.Errorf("清除 SSH 握手超时失败：%w", err)
	}
	client := ssh.NewClient(conn, channels, requests)

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		client.Close()
		raw.Close()
		return nil, net.ErrClosed
	}
	m.client = client
	m.raw = raw
	// 第一次连接后固定实际服务器 IP。全局路由启用后即使 SSH 断线，
	// 重连也不依赖可能需要当前 SSH 通道才能工作的系统 DNS。
	if tcpAddress, ok := raw.RemoteAddr().(*net.TCPAddr); ok {
		m.serverIP = append(net.IP(nil), tcpAddress.IP...)
		m.dialAddr = net.JoinHostPort(tcpAddress.IP.String(), fmt.Sprint(tcpAddress.Port))
	}
	m.mu.Unlock()

	m.logger.Info("SSH 连接已建立", "地址", address)
	m.wg.Add(1)
	go m.keepalive(client)
	return client, nil
}

func (m *Manager) cachedDialAddress(fallback string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.dialAddr != "" {
		return m.dialAddr
	}
	return fallback
}

// ServerIP 返回当前 SSH TCP 连接实际使用的服务器 IP，供全局模式添加直连路由。
func (m *Manager) ServerIP() (net.IP, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.serverIP) == 0 {
		return nil, errors.New("SSH 连接尚未提供服务器 IP")
	}
	return append(net.IP(nil), m.serverIP...), nil
}

func (m *Manager) currentClient() *ssh.Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.client
}

// DialContext 通过 SSH direct-tcpip 通道连接目标地址。
func (m *Manager) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	client, err := m.ensureConnected(ctx)
	if err != nil {
		return nil, err
	}
	releaseTarget, err := m.acquireTargetDial(ctx, address)
	if err != nil {
		return nil, err
	}
	select {
	case m.dialSlots <- struct{}{}:
	case <-ctx.Done():
		releaseTarget()
		return nil, ctx.Err()
	case <-m.done:
		releaseTarget()
		return nil, net.ErrClosed
	}

	type result struct {
		conn net.Conn
		err  error
	}
	// 使用无缓冲通道很重要：调用方超时返回后，后台稍晚建立的连接只能走
	// ctx.Done 分支并被关闭，不能遗留在无人接收的缓冲通道里。
	resultCh := make(chan result)
	go func() {
		defer func() {
			<-m.dialSlots
			releaseTarget()
		}()
		conn, err := client.Dial(network, address)
		select {
		case resultCh <- result{conn: conn, err: err}:
		case <-ctx.Done():
			if conn != nil {
				conn.Close()
			}
		case <-m.done:
			if conn != nil {
				conn.Close()
			}
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.done:
		return nil, net.ErrClosed
	case result := <-resultCh:
		if result.err != nil && isTransportClosed(result.err) {
			m.invalidate(client, result.err)
		}
		return result.conn, result.err
	}
}

func (m *Manager) acquireTargetDial(ctx context.Context, address string) (func(), error) {
	m.dialMu.Lock()
	state := m.targets[address]
	if state == nil {
		state = &targetDialState{slots: make(chan struct{}, maxPendingSSHToOneTarget)}
		m.targets[address] = state
	}
	state.users++
	m.dialMu.Unlock()

	select {
	case state.slots <- struct{}{}:
		return func() {
			<-state.slots
			m.releaseTargetDial(address, state)
		}, nil
	case <-ctx.Done():
		m.releaseTargetDial(address, state)
		return nil, ctx.Err()
	case <-m.done:
		m.releaseTargetDial(address, state)
		return nil, net.ErrClosed
	}
}

func (m *Manager) releaseTargetDial(address string, state *targetDialState) {
	m.dialMu.Lock()
	state.users--
	if state.users == 0 && m.targets[address] == state {
		delete(m.targets, address)
	}
	m.dialMu.Unlock()
}

func isTransportClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "connection lost")
}

func (m *Manager) keepalive(client *ssh.Client) {
	defer m.wg.Done()
	ticker := time.NewTicker(m.cfg.KeepaliveInterval())
	defer ticker.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
		}
		result := make(chan error, 1)
		// OpenSSH 对未知全局请求会返回 false；没有传输错误就代表链路仍然存活。
		go func() {
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			result <- err
		}()
		select {
		case err := <-result:
			if err != nil {
				m.invalidate(client, err)
				return
			}
		case <-time.After(m.cfg.ConnectTimeout()):
			m.invalidate(client, errors.New("SSH 保活请求超时"))
			return
		case <-m.done:
			return
		}
		if m.currentClient() != client {
			return
		}
	}
}

func (m *Manager) invalidate(client *ssh.Client, cause error) {
	m.mu.Lock()
	if m.client != client {
		m.mu.Unlock()
		return
	}
	raw := m.raw
	m.client = nil
	m.raw = nil
	m.mu.Unlock()

	m.logger.Warn("SSH 连接已断开，下一个 SOCKS5 请求将自动重连", "错误", cause)
	client.Close()
	if raw != nil {
		raw.Close()
	}
}

// Close 关闭当前 SSH 连接，并等待保活协程退出。
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	close(m.done)
	client := m.client
	raw := m.raw
	m.client = nil
	m.raw = nil
	m.mu.Unlock()

	if client != nil {
		client.Close()
	}
	if raw != nil {
		raw.Close()
	}
	m.wg.Wait()
	return nil
}
