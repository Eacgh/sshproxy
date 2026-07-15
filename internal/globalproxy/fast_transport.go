package globalproxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	tcpDialTimeout   = 6 * time.Second
	tcpHalfCloseTime = 60 * time.Second
	tcpRelayBuffer   = 128 << 10
	udpRelayBuffer   = (1 << 16) - 1
	dialLogInterval  = 10 * time.Second
)

var tcpBufferPool = sync.Pool{New: func() any { return make([]byte, tcpRelayBuffer) }}
var udpBufferPool = sync.Pool{New: func() any { return make([]byte, udpRelayBuffer) }}

type dialLogState struct {
	lastLogged time.Time
	suppressed int
}

// fastTransportHandler 是面向 SSH 通道优化的 tun2socks 传输处理器。
// 相比通用处理器，它移除了逐次读写的统计原子操作，并使用更大的复制缓冲区减少 SSH 包装调用。
type fastTransportHandler struct {
	transport *sshTransport
	logger    *slog.Logger

	mu          sync.Mutex
	connections map[net.Conn]struct{}
	closed      bool
	wg          sync.WaitGroup

	logMu    sync.Mutex
	dialLogs map[string]dialLogState
}

func newFastTransportHandler(dialer Dialer, dnsServer string, logger *slog.Logger) *fastTransportHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &fastTransportHandler{
		transport:   newSSHTransport(dialer, dnsServer, logger),
		logger:      logger,
		connections: make(map[net.Conn]struct{}),
		dialLogs:    make(map[string]dialLogState),
	}
}

func (h *fastTransportHandler) HandleTCP(origin adapter.TCPConn) {
	if !h.begin(origin) {
		origin.Close()
		return
	}
	go func() {
		defer h.finish(origin)
		h.handleTCP(origin)
	}()
}

func (h *fastTransportHandler) handleTCP(origin adapter.TCPConn) {
	defer origin.Close()
	metadata, err := metadataFromEndpoint(origin.ID(), M.TCP)
	if err != nil {
		h.logger.Debug("解析全局 TCP 目标失败", "错误", err)
		return
	}
	var initial []byte
	var serverName string
	if metadata.DstPort == 443 {
		if mappedName, ok := h.transport.mappedServerName(metadata); ok {
			serverName = mappedName
		} else {
			initial, serverName, err = sniffTLSServerName(origin)
			if err != nil && len(initial) == 0 && !isTimeoutFailure(err) {
				return
			}
		}
	}
	forwardTarget := h.transport.targetAddress(metadata, serverName)
	ctx, cancel := context.WithTimeout(context.Background(), tcpDialTimeout)
	dialStarted := time.Now()
	remote, err := h.transport.DialContextWithServerName(ctx, metadata, serverName)
	dialDuration := time.Since(dialStarted)
	cancel()
	if err != nil {
		h.logDialFailure(forwardTarget, err)
		return
	}
	if dialDuration >= time.Second {
		h.logger.Debug("全局 TCP 通道建立较慢", "目标", forwardTarget, "等待及SSH建连耗时", dialDuration.Round(10*time.Millisecond))
	}
	if !h.track(remote) {
		remote.Close()
		return
	}
	defer func() {
		h.untrack(remote)
		remote.Close()
	}()
	if err := writeAll(remote, initial); err != nil {
		h.logDialFailure(forwardTarget, err)
		return
	}

	relayTCP(origin, remote)
}

func writeAll(connection net.Conn, payload []byte) error {
	for len(payload) > 0 {
		written, err := connection.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
		payload = payload[written:]
	}
	return nil
}

func (h *fastTransportHandler) logDialFailure(target string, err error) {
	now := time.Now()
	h.logMu.Lock()
	state := h.dialLogs[target]
	if !state.lastLogged.IsZero() && now.Sub(state.lastLogged) < dialLogInterval {
		state.suppressed++
		h.dialLogs[target] = state
		h.logMu.Unlock()
		return
	}
	suppressed := state.suppressed
	h.dialLogs[target] = dialLogState{lastLogged: now}
	h.logMu.Unlock()
	errorMessage := localizedDialError(err)

	if suppressed > 0 {
		h.logger.Debug("建立全局 TCP 通道失败", "目标", target, "错误", errorMessage, "已省略重复", suppressed)
		return
	}
	h.logger.Debug("建立全局 TCP 通道失败", "目标", target, "错误", errorMessage)
}

func localizedDialError(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "连接目标超时"
	case errors.Is(err, context.Canceled):
		return "连接已取消"
	case errors.Is(err, net.ErrClosed):
		return "连接已经关闭"
	case isTimeoutFailure(err):
		return "连接目标超时"
	default:
		return err.Error()
	}
}

func relayTCP(origin, remote net.Conn) {
	done := make(chan struct{}, 2)
	go copyTCP(remote, origin, done)
	go copyTCP(origin, remote, done)
	<-done
	<-done
}

func copyTCP(destination, source net.Conn, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	buffer := tcpBufferPool.Get().([]byte)
	_, _ = io.CopyBuffer(destination, source, buffer)
	tcpBufferPool.Put(buffer)
	if closeReader, ok := source.(interface{ CloseRead() error }); ok {
		_ = closeReader.CloseRead()
	}
	if closeWriter, ok := destination.(interface{ CloseWrite() error }); ok {
		_ = closeWriter.CloseWrite()
	}
	_ = destination.SetReadDeadline(time.Now().Add(tcpHalfCloseTime))
}

func (h *fastTransportHandler) HandleUDP(origin adapter.UDPConn) {
	if !h.begin(origin) {
		origin.Close()
		return
	}
	go func() {
		defer h.finish(origin)
		h.handleUDP(origin)
	}()
}

func (h *fastTransportHandler) handleUDP(origin adapter.UDPConn) {
	defer origin.Close()
	metadata, err := metadataFromEndpoint(origin.ID(), M.UDP)
	if err != nil {
		return
	}
	remote, err := h.transport.DialUDP(metadata)
	if err != nil {
		return
	}
	defer remote.Close()
	target := metadata.UDPAddr()

	done := make(chan struct{}, 2)
	go copyUDP(remote, origin, target, done)
	go copyUDP(origin, remote, nil, done)
	<-done
	// 任一方向结束后关闭两端，让另一个复制协程立即退出。
	origin.Close()
	remote.Close()
	<-done
}

func copyUDP(destination, source net.PacketConn, target net.Addr, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	buffer := udpBufferPool.Get().([]byte)
	defer udpBufferPool.Put(buffer)
	for {
		_ = source.SetReadDeadline(time.Now().Add(60 * time.Second))
		read, _, err := source.ReadFrom(buffer)
		if err != nil {
			return
		}
		if _, err := destination.WriteTo(buffer[:read], target); err != nil {
			return
		}
	}
}

func metadataFromEndpoint(id *stack.TransportEndpointID, network M.Network) (*M.Metadata, error) {
	if id == nil {
		return nil, errors.New("缺少传输端点信息")
	}
	source, ok := netipFromTCPIPAddress(id.RemoteAddress)
	if !ok {
		return nil, errors.New("源 IP 地址无效")
	}
	destination, ok := netipFromTCPIPAddress(id.LocalAddress)
	if !ok {
		return nil, errors.New("目标 IP 地址无效")
	}
	return &M.Metadata{
		Network: network,
		SrcIP:   source,
		SrcPort: id.RemotePort,
		DstIP:   destination,
		DstPort: id.LocalPort,
	}, nil
}

func netipFromTCPIPAddress(address tcpip.Address) (netip.Addr, bool) {
	value, ok := netip.AddrFromSlice(address.AsSlice())
	if !ok {
		return netip.Addr{}, false
	}
	return value.Unmap(), true
}

func (h *fastTransportHandler) begin(connection net.Conn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return false
	}
	h.connections[connection] = struct{}{}
	h.wg.Add(1)
	return true
}

func (h *fastTransportHandler) finish(connection net.Conn) {
	h.untrack(connection)
	h.wg.Done()
}

func (h *fastTransportHandler) track(connection net.Conn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return false
	}
	h.connections[connection] = struct{}{}
	return true
}

func (h *fastTransportHandler) untrack(connection net.Conn) {
	h.mu.Lock()
	delete(h.connections, connection)
	h.mu.Unlock()
}

func (h *fastTransportHandler) Close() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	connections := make([]net.Conn, 0, len(h.connections))
	for connection := range h.connections {
		connections = append(connections, connection)
	}
	h.mu.Unlock()
	for _, connection := range connections {
		connection.Close()
	}
	h.wg.Wait()
	h.transport.Close()
}
