package globalproxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"sshvpn/internal/config"
	"sshvpn/internal/stats"
)

const (
	// 建连超时要覆盖 SSH 通道建立、服务器端解析域名和连接目标的完整过程；
	// 太短会把慢链路误判为不可达并触发熔断，导致页面整体不可用。
	tcpDialTimeout    = 15 * time.Second
	tcpHalfCloseTime  = 15 * time.Second
	tcpRelayBuffer    = 32 << 10
	udpRelayBuffer    = 16 << 10
	udpIdleTimeout    = 30 * time.Second
	dialLogInterval   = 10 * time.Second
	maxDirectUDPFlows = 512
)

var (
	tcpHalfCloseTimeout = tcpHalfCloseTime
	tcpBufferPool       = sync.Pool{New: func() any { return make([]byte, tcpRelayBuffer) }}
	udpBufferPool       = sync.Pool{New: func() any { return make([]byte, udpRelayBuffer) }}
	wintunIPv4Prefix    = netip.MustParsePrefix("198.18.0.0/24")
	wintunIPv6Addr      = netip.MustParseAddr("fd00::1")
	wintunDNSIPv6Addr   = netip.MustParseAddr("fd00::2")
)

type flowRoute uint8

const (
	flowRouteDirect flowRoute = iota
	flowRouteProxy
	flowRouteDrop
)

type localPortOwner interface {
	OwnsLocalUDPPort(ipv6 bool, port uint16) bool
}

// isNonForwardableDirectDest 过滤不可通过物理网卡直连转发的目标地址，
// 防止发往 Wintun 网段/网关或二层多播/广播的流量再次回灌入虚拟网卡形成回环。
func isNonForwardableDirectDest(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() ||
		addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return true
	}
	if addr.Is4() {
		return addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || wintunIPv4Prefix.Contains(addr)
	}
	return addr == wintunIPv6Addr || addr == wintunDNSIPv6Addr
}

type dialLogState struct {
	lastLogged time.Time
	suppressed int
}

type directTransport interface {
	DialTCP(ctx context.Context, address string) (net.Conn, error)
	ListenUDP(ipv6 bool) (net.PacketConn, error)
	ResolveIPv4(ctx context.Context, host string) (netip.Addr, error)
}

type fastTransportConfig struct {
	dialer       Dialer
	dnsServer    string
	logger       *slog.Logger
	traffic      *stats.Traffic
	mode         config.ProxyMode
	processRules []config.ProcessRule
	lookup       processLookup
	direct       directTransport
}

type flowAbortTarget struct {
	cancel context.CancelFunc
	origin io.Closer
	remote io.Closer
}

func closeFlowTargets(targets []flowAbortTarget) {
	for _, target := range targets {
		if target.cancel != nil {
			target.cancel()
		}
		if target.origin != nil {
			_ = target.origin.Close()
		}
		if target.remote != nil {
			_ = target.remote.Close()
		}
	}
}

type trackedFlow struct {
	origin     io.Closer
	remote     io.Closer
	ctx        context.Context
	cancel     context.CancelFunc
	classified bool
	pid        uint32
	paths      []string
	proxied    bool
	aborted    bool
}

// fastTransportHandler 是面向 SSH 通道优化的 tun2socks 传输处理器。
// 相比通用处理器，它移除了逐次读写的统计原子操作，并使用更大的复制缓冲区减少 SSH 包装调用；
// 在按进程分流模式下支持依据源端口反查进程并将非目标流量直连物理网卡。
type fastTransportHandler struct {
	transport      *sshTransport
	logger         *slog.Logger
	stats          *stats.Traffic
	mode           config.ProxyMode
	matcher        *ProcessMatcher
	lookup         processLookup
	direct         directTransport
	selfPID        uint32
	directUDPSlots chan struct{}

	mu     sync.Mutex
	flows  map[*trackedFlow]struct{}
	closed bool
	wg     sync.WaitGroup

	logMu    sync.Mutex
	dialLogs map[string]dialLogState
}

func newFastTransportHandler(dialer Dialer, dnsServer string, logger *slog.Logger) *fastTransportHandler {
	return newFastTransportHandlerWithStats(dialer, dnsServer, logger, nil)
}

func newFastTransportHandlerWithStats(dialer Dialer, dnsServer string, logger *slog.Logger, traffic *stats.Traffic) *fastTransportHandler {
	return newFastTransportHandlerWithConfig(fastTransportConfig{
		dialer:    dialer,
		dnsServer: dnsServer,
		logger:    logger,
		traffic:   traffic,
		mode:      config.ModeGlobal,
	})
}

func newFastTransportHandlerWithConfig(cfg fastTransportConfig) *fastTransportHandler {
	logger := cfg.logger
	if logger == nil {
		logger = slog.Default()
	}
	traffic := cfg.traffic
	if traffic == nil {
		traffic = new(stats.Traffic)
	}
	mode := cfg.mode
	if mode == "" {
		mode = config.ModeGlobal
	}
	return &fastTransportHandler{
		transport:      newSSHTransport(cfg.dialer, cfg.dnsServer, logger),
		logger:         logger,
		stats:          traffic,
		mode:           mode,
		matcher:        NewProcessMatcher(cfg.processRules),
		lookup:         cfg.lookup,
		direct:         cfg.direct,
		selfPID:        uint32(os.Getpid()),
		directUDPSlots: make(chan struct{}, maxDirectUDPFlows),
		flows:          make(map[*trackedFlow]struct{}),
		dialLogs:       make(map[string]dialLogState),
	}
}

// SetProcessRules 原子替换按进程分流规则，并立即取消或断开路由方向发生变化的活动连接，
// 使动态新增、禁用或移除白名单进程无需等待长连接自然关闭即可实时切换。
func (h *fastTransportHandler) SetProcessRules(rules []config.ProcessRule) int {
	var toAbort []flowAbortTarget

	h.mu.Lock()
	if h.matcher != nil {
		h.matcher.SetRules(rules)
	}
	if h.mode == config.ModeProcess && !h.closed {
		for flow := range h.flows {
			if !flow.classified || flow.aborted {
				continue
			}
			nowProxied := false
			if flow.pid != 0 && flow.pid != h.selfPID && h.matcher != nil {
				_, nowProxied = h.matcher.MatchAny(flow.paths)
			}
			if nowProxied != flow.proxied {
				flow.aborted = true
				toAbort = append(toAbort, flowAbortTarget{
					cancel: flow.cancel,
					origin: flow.origin,
					remote: flow.remote,
				})
			}
		}
	}
	h.mu.Unlock()

	closeFlowTargets(toAbort)
	return len(toAbort)
}

func (h *fastTransportHandler) HandleTCP(origin adapter.TCPConn) {
	flow, ok := h.beginFlow(origin)
	if !ok {
		origin.Close()
		return
	}
	go func() {
		defer h.finishFlow(flow)
		h.handleTCPFlow(flow, origin)
	}()
}

func (h *fastTransportHandler) handleTCP(origin adapter.TCPConn) {
	flow, ok := h.beginFlow(origin)
	if !ok {
		origin.Close()
		return
	}
	defer h.finishFlow(flow)
	h.handleTCPFlow(flow, origin)
}

func (h *fastTransportHandler) handleTCPFlow(flow *trackedFlow, origin adapter.TCPConn) {
	defer origin.Close()
	metadata, err := metadataFromEndpoint(origin.ID(), M.TCP)
	if err != nil {
		h.logger.Debug("解析全局 TCP 目标失败", "错误", err)
		return
	}
	if metadata.DstPort != 53 && h.mode == config.ModeProcess {
		id, ok := h.lookupTCPProcess(metadata)
		route, matchedBy, aborted := h.classifyFlow(flow, id, ok)
		if aborted || route == flowRouteDrop {
			return
		}
		if route == flowRouteDirect {
			h.handleDirectTCP(flow, origin, metadata, id.Path)
			return
		}
		h.handleProxyTCP(flow, origin, metadata, id.Path, matchedBy)
		return
	}
	h.handleProxyTCP(flow, origin, metadata, "", "")
}

func (h *fastTransportHandler) lookupTCPProcess(metadata *M.Metadata) (ProcessIdentity, bool) {
	if h.lookup == nil {
		return ProcessIdentity{}, false
	}
	return h.lookup.LookupTCP(metadata.SrcIP, metadata.SrcPort, metadata.DstIP, metadata.DstPort)
}

func (h *fastTransportHandler) lookupUDPProcess(metadata *M.Metadata) (ProcessIdentity, bool) {
	if h.lookup == nil {
		return ProcessIdentity{}, false
	}
	return h.lookup.LookupUDP(metadata.SrcIP, metadata.SrcPort)
}

func (h *fastTransportHandler) classifyFlow(flow *trackedFlow, id ProcessIdentity, ok bool) (flowRoute, string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || flow.aborted {
		return flowRouteDrop, "", true
	}
	if ok && id.PID == h.selfPID {
		// 严禁把本进程自己发起的连接（例如直连套接字或 SSH）再经虚拟网卡回送，否则会形成自激放大回环。
		flow.classified = false
		return flowRouteDrop, "", false
	}
	flow.classified = true
	if ok && id.PID != 0 {
		flow.pid = id.PID
		flow.paths = append([]string(nil), id.Paths...)
		if h.matcher != nil {
			if matched, hit := h.matcher.MatchAny(id.Paths); hit {
				flow.proxied = true
				return flowRouteProxy, matched, false
			}
		}
	}
	return flowRouteDirect, "", false
}

func (h *fastTransportHandler) handleProxyTCP(flow *trackedFlow, origin adapter.TCPConn, metadata *M.Metadata, processPath, matchedBy string) {
	if flow.ctx.Err() != nil {
		return
	}
	isFake := isFakeAddress(metadata.DstIP)
	var initial []byte
	var serverName string
	if mappedName, ok := h.transport.mappedServerName(metadata); ok {
		serverName = mappedName
	} else if metadata.DstPort == 443 {
		var err error
		initial, serverName, err = sniffTLSServerName(origin)
		if err != nil && len(initial) == 0 && !isTimeoutFailure(err) {
			return
		}
		if flow.ctx.Err() != nil {
			return
		}
		if isFake && serverName == "" {
			// 目标 DstIP 是缓存的过期 Fake-IP 且未提取到 SNI，直接关闭让上层
			// 重新解析 DNS 拿到新映射，避免把它当真实地址拨号触发熔断。
			h.logger.Debug("忽略未命中映射的过期 Fake-IP 连接", "目标", metadata.DestinationAddress())
			return
		}
	} else if isFake {
		h.logger.Debug("忽略未命中映射的过期 Fake-IP 连接", "目标", metadata.DestinationAddress())
		return
	}
	if flow.ctx.Err() != nil {
		return
	}
	forwardTarget := h.transport.targetAddress(metadata, serverName)
	ctx, cancel := context.WithTimeout(flow.ctx, tcpDialTimeout)
	dialStarted := time.Now()
	remote, err := h.transport.DialContextWithServerName(ctx, metadata, serverName)
	dialDuration := time.Since(dialStarted)
	cancel()
	if err != nil {
		if flow.ctx.Err() == nil {
			h.logDialFailure(forwardTarget, err)
		}
		return
	}
	h.clearDialLog(forwardTarget)
	if dialDuration >= time.Second {
		h.logger.Debug("全局 TCP 通道建立较慢", "目标", forwardTarget, "等待及SSH建连耗时", dialDuration.Round(10*time.Millisecond))
	}
	if !h.attachRemote(flow, remote) {
		remote.Close()
		return
	}
	defer func() {
		h.detachRemote(flow, remote)
		remote.Close()
	}()
	if err := writeAll(remote, initial); err != nil {
		if flow.ctx.Err() == nil {
			h.logDialFailure(forwardTarget, err)
		}
		return
	}
	if len(initial) > 0 {
		h.stats.Add(uint64(len(initial)), 0)
	}
	if processPath != "" {
		if matchedBy != "" && !strings.EqualFold(matchedBy, processPath) {
			h.logger.Debug("进程代理 TCP 通道已建立", "目标", forwardTarget, "进程", processPath, "命中祖先", matchedBy)
		} else {
			h.logger.Debug("进程代理 TCP 通道已建立", "目标", forwardTarget, "进程", processPath)
		}
	} else {
		h.logger.Debug("全局 TCP 通道已建立", "目标", forwardTarget)
	}

	h.relayTCP(origin, remote, h.stats)
}

func (h *fastTransportHandler) handleDirectTCP(flow *trackedFlow, origin adapter.TCPConn, metadata *M.Metadata, processPath string) {
	if h.direct == nil || flow.ctx.Err() != nil {
		return
	}
	isFake := isFakeAddress(metadata.DstIP)
	if !isFake && isNonForwardableDirectDest(metadata.DstIP) {
		return
	}
	var initial []byte
	var domain string
	if mappedName, ok := h.transport.mappedServerName(metadata); ok {
		domain = mappedName
	} else if metadata.DstPort == 443 {
		var err error
		initial, domain, err = sniffTLSServerName(origin)
		if err != nil && len(initial) == 0 && !isTimeoutFailure(err) {
			return
		}
		if flow.ctx.Err() != nil {
			return
		}
		if isFake && domain == "" {
			h.logger.Debug("直连旁路忽略未命中映射的过期 Fake-IP", "目标", metadata.DestinationAddress())
			return
		}
	} else if isFake {
		h.logger.Debug("直连旁路忽略未命中映射的过期 Fake-IP", "目标", metadata.DestinationAddress())
		return
	}
	if flow.ctx.Err() != nil {
		return
	}

	ctx, cancel := context.WithTimeout(flow.ctx, tcpDialTimeout)
	defer cancel()

	dialTarget := metadata.DestinationAddress()
	if isFake {
		resolvedIP, err := h.direct.ResolveIPv4(ctx, domain)
		if err != nil {
			if flow.ctx.Err() == nil {
				h.logger.Debug("直连进程解析域名失败", "进程", processPath, "域名", domain, "错误", err)
			}
			return
		}
		if isNonForwardableDirectDest(resolvedIP) {
			return
		}
		dialTarget = net.JoinHostPort(resolvedIP.String(), strconv.Itoa(int(metadata.DstPort)))
	}

	remote, err := h.direct.DialTCP(ctx, dialTarget)
	if err != nil {
		if flow.ctx.Err() == nil && !errors.Is(err, errNoDirectIPv6) && !errors.Is(err, errNoDirectIPv4) {
			h.logger.Debug("直连 TCP 通道失败", "进程", processPath, "目标", dialTarget, "错误", err)
		}
		return
	}
	if !h.attachRemote(flow, remote) {
		remote.Close()
		return
	}
	defer func() {
		h.detachRemote(flow, remote)
		remote.Close()
	}()
	if err := writeAll(remote, initial); err != nil {
		return
	}
	h.logger.Debug("直连 TCP 通道已建立", "进程", processPath, "目标", dialTarget)
	h.relayTCP(origin, remote, nil)
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
	if len(h.dialLogs) >= 256 {
		for k, entry := range h.dialLogs {
			if now.Sub(entry.lastLogged) > 5*time.Minute {
				delete(h.dialLogs, k)
			}
		}
	}
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

// clearDialLog 在目标恢复成功后清理其失败日志状态，避免日志表随失败
// 目标数量无限增长。
func (h *fastTransportHandler) clearDialLog(target string) {
	h.logMu.Lock()
	delete(h.dialLogs, target)
	h.logMu.Unlock()
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

func (h *fastTransportHandler) relayTCP(origin, remote net.Conn, traffic *stats.Traffic) {
	done := make(chan struct{}, 2)
	go h.copyTCP(remote, origin, done, true, traffic)  // 本机 -> 远端：上行
	go h.copyTCP(origin, remote, done, false, traffic) // 远端 -> 本机：下行
	<-done
	timer := time.NewTimer(tcpHalfCloseTimeout)
	select {
	case <-done:
		timer.Stop()
	case <-timer.C:
		// 强制收尾半关闭超时：ssh.Channel 不支持 SetReadDeadline，
		// 若远端对 CloseWrite 后长期不返回 EOF，超时直接关闭两端以释放协程和缓冲。
		_ = origin.Close()
		_ = remote.Close()
		<-done
	}
}

func (h *fastTransportHandler) copyTCP(destination, source net.Conn, done chan<- struct{}, upload bool, traffic *stats.Traffic) {
	defer func() { done <- struct{}{} }()
	buffer := tcpBufferPool.Get().([]byte)
	_, _ = traffic.CopyBuffer(destination, source, buffer, upload)
	tcpBufferPool.Put(buffer)
	if closeReader, ok := source.(interface{ CloseRead() error }); ok {
		_ = closeReader.CloseRead()
	}
	if closeWriter, ok := destination.(interface{ CloseWrite() error }); ok {
		_ = closeWriter.CloseWrite()
	}
	_ = destination.SetReadDeadline(time.Now().Add(tcpHalfCloseTimeout))
}

func (h *fastTransportHandler) HandleUDP(origin adapter.UDPConn) {
	flow, ok := h.beginFlow(origin)
	if !ok {
		origin.Close()
		return
	}
	go func() {
		defer h.finishFlow(flow)
		h.handleUDPFlow(flow, origin)
	}()
}

func (h *fastTransportHandler) handleUDP(origin adapter.UDPConn) {
	flow, ok := h.beginFlow(origin)
	if !ok {
		origin.Close()
		return
	}
	defer h.finishFlow(flow)
	h.handleUDPFlow(flow, origin)
}

func (h *fastTransportHandler) handleUDPFlow(flow *trackedFlow, origin adapter.UDPConn) {
	defer origin.Close()
	metadata, err := metadataFromEndpoint(origin.ID(), M.UDP)
	if err != nil {
		return
	}
	if metadata.DstPort != 53 && h.mode == config.ModeProcess {
		if owner, ok := h.direct.(localPortOwner); ok && owner.OwnsLocalUDPPort(metadata.SrcIP.Is6(), metadata.SrcPort) {
			return
		}
		id, ok := h.lookupUDPProcess(metadata)
		route, _, aborted := h.classifyFlow(flow, id, ok)
		if aborted || route == flowRouteDrop {
			return
		}
		if route == flowRouteProxy {
			h.logger.Debug("已阻止白名单进程的非 DNS UDP 流量，促使回退到 TCP", "进程", id.Path, "目标", metadata.DestinationAddress())
			return
		}
		h.handleDirectUDP(flow, origin, metadata)
		return
	}
	if flow.ctx.Err() != nil {
		return
	}
	remote, err := h.transport.DialUDP(metadata)
	if err != nil {
		return
	}
	if !h.attachRemote(flow, remote) {
		remote.Close()
		return
	}
	defer func() {
		h.detachRemote(flow, remote)
		remote.Close()
	}()
	relayUDP(origin, remote, metadata.UDPAddr())
}

func (h *fastTransportHandler) handleDirectUDP(flow *trackedFlow, origin adapter.UDPConn, metadata *M.Metadata) {
	if h.direct == nil || flow.ctx.Err() != nil {
		return
	}
	isFake := isFakeAddress(metadata.DstIP)
	if !isFake && isNonForwardableDirectDest(metadata.DstIP) {
		return
	}
	if h.directUDPSlots != nil {
		select {
		case h.directUDPSlots <- struct{}{}:
			defer func() { <-h.directUDPSlots }()
		default:
			return
		}
	}
	useIPv6 := metadata.DstIP.Is6()
	var targetAddr *net.UDPAddr
	if isFake {
		name, ok := h.transport.mappedServerName(metadata)
		if !ok || name == "" {
			return
		}
		ctx, cancel := context.WithTimeout(flow.ctx, directDNSTimeout)
		resolvedIP, err := h.direct.ResolveIPv4(ctx, name)
		cancel()
		if err != nil {
			if flow.ctx.Err() == nil {
				h.logger.Debug("直连 UDP 解析域名失败", "域名", name, "错误", err)
			}
			return
		}
		if isNonForwardableDirectDest(resolvedIP) {
			return
		}
		targetAddr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(resolvedIP, metadata.DstPort))
		useIPv6 = false
	} else {
		targetAddr = metadata.UDPAddr()
	}
	if targetAddr == nil || flow.ctx.Err() != nil {
		return
	}

	remote, err := h.direct.ListenUDP(useIPv6)
	if err != nil {
		if !errors.Is(err, errNoDirectIPv6) && !errors.Is(err, errNoDirectIPv4) {
			h.logger.Debug("创建直连 UDP 套接字失败", "目标", targetAddr.String(), "错误", err)
		}
		return
	}
	if !h.attachRemote(flow, remote) {
		remote.Close()
		return
	}
	defer func() {
		h.detachRemote(flow, remote)
		remote.Close()
	}()

	relayUDP(origin, remote, targetAddr)
}

func relayUDP(origin, remote net.PacketConn, target net.Addr) {
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
		_ = source.SetReadDeadline(time.Now().Add(udpIdleTimeout))
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

func (h *fastTransportHandler) beginFlow(origin io.Closer) (*trackedFlow, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, false
	}
	ctx, cancel := context.WithCancel(context.Background())
	flow := &trackedFlow{
		origin: origin,
		ctx:    ctx,
		cancel: cancel,
	}
	h.flows[flow] = struct{}{}
	h.wg.Add(1)
	return flow, true
}

func (h *fastTransportHandler) finishFlow(flow *trackedFlow) {
	if flow == nil {
		return
	}
	if flow.cancel != nil {
		flow.cancel()
	}
	h.mu.Lock()
	delete(h.flows, flow)
	h.mu.Unlock()
	h.wg.Done()
}

func (h *fastTransportHandler) attachRemote(flow *trackedFlow, remote io.Closer) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || flow.aborted {
		return false
	}
	flow.remote = remote
	return true
}

func (h *fastTransportHandler) detachRemote(flow *trackedFlow, remote io.Closer) {
	h.mu.Lock()
	if flow.remote == remote {
		flow.remote = nil
	}
	h.mu.Unlock()
}

func (h *fastTransportHandler) Close() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	toAbort := make([]flowAbortTarget, 0, len(h.flows))
	for flow := range h.flows {
		flow.aborted = true
		toAbort = append(toAbort, flowAbortTarget{
			cancel: flow.cancel,
			origin: flow.origin,
			remote: flow.remote,
		})
	}
	h.mu.Unlock()

	closeFlowTargets(toAbort)
	h.wg.Wait()
	h.transport.Close()
}
