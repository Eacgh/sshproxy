package globalproxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"sshvpn/internal/config"
	"sshvpn/internal/stats"
)

func TestMetadataFromEndpoint(t *testing.T) {
	metadata, err := metadataFromEndpoint(&stack.TransportEndpointID{
		RemoteAddress: tcpip.AddrFrom4([4]byte{192, 0, 2, 10}),
		RemotePort:    50000,
		LocalAddress:  tcpip.AddrFrom4([4]byte{203, 0, 113, 20}),
		LocalPort:     443,
	}, M.TCP)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.SourceAddress() != "192.0.2.10:50000" {
		t.Fatalf("源地址为 %q", metadata.SourceAddress())
	}
	if metadata.DestinationAddress() != "203.0.113.20:443" {
		t.Fatalf("目标地址为 %q", metadata.DestinationAddress())
	}
}

func TestRelayTCPTransfersBothDirections(t *testing.T) {
	originClient, originTunnel := net.Pipe()
	remoteTunnel, remoteServer := net.Pipe()
	defer originClient.Close()
	defer remoteServer.Close()

	handler := newFastTransportHandlerWithStats(dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("中继测试不应建立 SSH 通道")
		return nil, nil
	}), "", slog.Default(), nil)

	relayDone := make(chan struct{})
	go func() {
		handler.relayTCP(originTunnel, remoteTunnel, handler.stats)
		close(relayDone)
	}()

	upload := bytes.Repeat([]byte("上传数据"), 256*1024)
	uploadDone := make(chan error, 1)
	go func() {
		_, err := originClient.Write(upload)
		uploadDone <- err
	}()
	receivedUpload := make([]byte, len(upload))
	if _, err := io.ReadFull(remoteServer, receivedUpload); err != nil {
		t.Fatal(err)
	}
	if err := <-uploadDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(receivedUpload, upload) {
		t.Fatal("上传内容不一致")
	}

	download := bytes.Repeat([]byte("下载数据"), 256*1024)
	downloadDone := make(chan error, 1)
	go func() {
		_, err := remoteServer.Write(download)
		downloadDone <- err
	}()
	receivedDownload := make([]byte, len(download))
	if _, err := io.ReadFull(originClient, receivedDownload); err != nil {
		t.Fatal(err)
	}
	if err := <-downloadDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(receivedDownload, download) {
		t.Fatal("下载内容不一致")
	}

	originClient.Close()
	remoteServer.Close()
	select {
	case <-relayDone:
	case <-time.After(3 * time.Second):
		t.Fatal("双向中继没有正常退出")
	}

	// 验证上下行统计：上传 = len(upload)，下载 = len(download)。
	uploadStats, downloadStats := handler.stats.Snapshot()
	if uploadStats != uint64(len(upload)) || downloadStats != uint64(len(download)) {
		t.Fatalf("流量统计 = %d/%d，期望 %d/%d", uploadStats, downloadStats, len(upload), len(download))
	}
}

type stubTCPConn struct {
	net.Conn
	id *stack.TransportEndpointID
}

func (c *stubTCPConn) ID() *stack.TransportEndpointID {
	return c.id
}

func TestHandleTCPDropsUnmappedFakeIP(t *testing.T) {
	for _, port := range []uint16{80, 443} {
		handler := newFastTransportHandlerWithStats(dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			t.Fatalf("未映射的 Fake-IP（端口 %d）不应触发拨号", port)
			return nil, nil
		}), "", slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

		originClient, originTunnel := net.Pipe()
		defer originClient.Close()
		conn := &stubTCPConn{
			Conn: originTunnel,
			id: &stack.TransportEndpointID{
				RemoteAddress: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}),
				RemotePort:    51000,
				LocalAddress:  tcpip.AddrFrom4([4]byte{198, 19, 0, 42}),
				LocalPort:     port,
			},
		}

		done := make(chan struct{})
		go func() {
			handler.handleTCP(conn)
			close(done)
		}()

		if port == 443 {
			// 发送非 TLS 明文数据，无法提取 SNI。
			_, _ = originClient.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
		}
		buf := make([]byte, 16)
		_ = originClient.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := originClient.Read(buf); err == nil {
			t.Fatalf("端口 %d 的未映射 Fake-IP 应被直接关闭", port)
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("端口 %d 的 handleTCP 没有及时退出", port)
		}
	}
}

func TestHandleTCPAllowsRealIP443AfterSNITimeout(t *testing.T) {
	var dialedTarget string
	remoteTunnel, remoteServer := net.Pipe()
	defer remoteServer.Close()

	handler := newFastTransportHandlerWithStats(dialerFunc(func(_ context.Context, _, address string) (net.Conn, error) {
		dialedTarget = address
		return remoteTunnel, nil
	}), "", slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	originClient, originTunnel := net.Pipe()
	defer originClient.Close()
	conn := &stubTCPConn{
		Conn: originTunnel,
		id: &stack.TransportEndpointID{
			RemoteAddress: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}),
			RemotePort:    52000,
			LocalAddress:  tcpip.AddrFrom4([4]byte{203, 0, 113, 8}),
			LocalPort:     443,
		},
	}

	done := make(chan struct{})
	go func() {
		handler.handleTCP(conn)
		close(done)
	}()

	// 客户端暂不发包，等待 300ms SNI 嗅探超时后应直连真实 IP，服务端先发数据能到达客户端。
	banner := []byte("SERVER-FIRST-BANNER")
	writeErr := make(chan error, 1)
	go func() {
		_, err := remoteServer.Write(banner)
		writeErr <- err
	}()

	received := make([]byte, len(banner))
	_ = originClient.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(originClient, received); err != nil {
		t.Fatalf("真实 IP 443 在 SNI 超时后未能正常转发：%v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
	if string(received) != string(banner) {
		t.Fatalf("转发数据不一致：%q", received)
	}
	if dialedTarget != "203.0.113.8:443" {
		t.Fatalf("拨号目标 = %q，期望 203.0.113.8:443", dialedTarget)
	}

	originClient.Close()
	remoteServer.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleTCP 没有正常退出")
	}
}

type stubProcessLookup struct {
	tcp map[uint16]ProcessIdentity
	udp map[uint16]ProcessIdentity
}

func (s *stubProcessLookup) LookupTCP(_ netip.Addr, srcPort uint16, _ netip.Addr, _ uint16) (ProcessIdentity, bool) {
	item, ok := s.tcp[srcPort]
	return item, ok
}

func (s *stubProcessLookup) LookupUDP(_ netip.Addr, srcPort uint16) (ProcessIdentity, bool) {
	item, ok := s.udp[srcPort]
	return item, ok
}

type stubDirectTransport struct {
	mu           sync.Mutex
	dialed       []string
	resolved     map[string]netip.Addr
	onDialTCP    func(ctx context.Context, address string) (net.Conn, error)
	onListenUDP  func(ipv6 bool) (net.PacketConn, error)
	listenCalled int
}

func (s *stubDirectTransport) DialTCP(ctx context.Context, address string) (net.Conn, error) {
	s.mu.Lock()
	s.dialed = append(s.dialed, address)
	s.mu.Unlock()
	return s.onDialTCP(ctx, address)
}

func (s *stubDirectTransport) ListenUDP(ipv6 bool) (net.PacketConn, error) {
	s.mu.Lock()
	s.listenCalled++
	s.mu.Unlock()
	return s.onListenUDP(ipv6)
}

func (s *stubDirectTransport) ResolveIPv4(_ context.Context, host string) (netip.Addr, error) {
	return s.resolved[host], nil
}

type pipeUDPConn struct {
	net.Conn
	id       *stack.TransportEndpointID
	in       chan []byte
	out      chan udpPacket
	closeMu  sync.Mutex
	closed   bool
	closedCh chan struct{}
}

type udpPacket struct {
	data []byte
	addr net.Addr
}

func newPipeUDPConn(id *stack.TransportEndpointID) *pipeUDPConn {
	return &pipeUDPConn{
		id:       id,
		in:       make(chan []byte, 4),
		out:      make(chan udpPacket, 4),
		closedCh: make(chan struct{}),
	}
}

func (c *pipeUDPConn) ID() *stack.TransportEndpointID { return c.id }
func (c *pipeUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case data := <-c.in:
		return copy(p, data), &net.UDPAddr{IP: net.IPv4(198, 18, 0, 1), Port: int(c.id.RemotePort)}, nil
	case <-c.closedCh:
		return 0, nil, net.ErrClosed
	}
}
func (c *pipeUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closedCh:
		return 0, net.ErrClosed
	default:
	}
	cp := append([]byte(nil), p...)
	c.out <- udpPacket{data: cp, addr: addr}
	return len(p), nil
}
func (c *pipeUDPConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *pipeUDPConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (c *pipeUDPConn) Close() error {
	c.closeMu.Lock()
	if !c.closed {
		c.closed = true
		close(c.closedCh)
	}
	c.closeMu.Unlock()
	return nil
}
func (c *pipeUDPConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *pipeUDPConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *pipeUDPConn) SetDeadline(time.Time) error      { return nil }
func (c *pipeUDPConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pipeUDPConn) SetWriteDeadline(time.Time) error { return nil }

type halfClosePipe struct {
	reader *io.PipeReader
	writer *io.PipeWriter
}

func newDuplexPipe() (*halfClosePipe, *halfClosePipe) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	return &halfClosePipe{reader: r2, writer: w1}, &halfClosePipe{reader: r1, writer: w2}
}

func (p *halfClosePipe) Read(b []byte) (int, error)         { return p.reader.Read(b) }
func (p *halfClosePipe) Write(b []byte) (int, error)        { return p.writer.Write(b) }
func (p *halfClosePipe) CloseWrite() error                  { return p.writer.Close() }
func (p *halfClosePipe) CloseRead() error                   { return p.reader.Close() }
func (p *halfClosePipe) Close() error                       { _ = p.writer.Close(); return p.reader.Close() }
func (p *halfClosePipe) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (p *halfClosePipe) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (p *halfClosePipe) SetDeadline(time.Time) error        { return nil }
func (p *halfClosePipe) SetReadDeadline(time.Time) error    { return nil }
func (p *halfClosePipe) SetWriteDeadline(time.Time) error   { return nil }

func startEchoPipe() net.Conn {
	c1, c2 := newDuplexPipe()
	go func() {
		defer c2.Close()
		_, _ = io.Copy(c2, c2)
	}()
	return c1
}

func TestModeProcessSplitsTCPBetweenSSHAndDirect(t *testing.T) {
	var sshMu sync.Mutex
	var sshDialed []string

	traffic := new(stats.Traffic)
	lookup := &stubProcessLookup{
		tcp: map[uint16]ProcessIdentity{
			51001: {
				PID:   1001,
				Path:  `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
				Paths: []string{`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`},
			},
			51002: {
				PID:   1002,
				Path:  `C:\Program Files\Mozilla Firefox\firefox.exe`,
				Paths: []string{`C:\Program Files\Mozilla Firefox\firefox.exe`},
			},
			51003: {
				PID:  1003,
				Path: `C:\Users\11750\AppData\Local\Programs\antigravity\resources\bin\language_server.exe`,
				Paths: []string{
					`C:\Users\11750\AppData\Local\Programs\antigravity\resources\bin\language_server.exe`,
					`C:\Users\11750\AppData\Local\Programs\antigravity\Antigravity.exe`,
				},
			},
		},
	}
	direct := &stubDirectTransport{
		resolved: map[string]netip.Addr{
			"firefox.test": netip.MustParseAddr("110.242.68.66"),
			"edge.test":    netip.MustParseAddr("110.242.68.77"),
		},
		onDialTCP: func(context.Context, string) (net.Conn, error) {
			return startEchoPipe(), nil
		},
	}

	handler := newFastTransportHandlerWithConfig(fastTransportConfig{
		dialer: dialerFunc(func(_ context.Context, _, address string) (net.Conn, error) {
			sshMu.Lock()
			sshDialed = append(sshDialed, address)
			sshMu.Unlock()
			return startEchoPipe(), nil
		}),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		traffic: traffic,
		mode:    config.ModeProcess,
		processRules: []config.ProcessRule{
			{Name: "msedge", Path: `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`},
			{Name: "Antigravity", Path: `C:\Users\11750\AppData\Local\Programs\antigravity\Antigravity.exe`},
		},
		lookup: lookup,
		direct: direct,
	})

	handler.transport.dnsNames.store("edge.test", netip.MustParseAddr("198.19.0.10"), time.Minute)
	handler.transport.dnsNames.storeResolved("firefox.test", netip.MustParseAddr("198.19.0.20"), netip.MustParseAddr("1.2.3.4"), time.Minute)

	sendAndEcho := func(srcPort uint16, dstIP [4]byte, payload string) {
		client, tunnel := net.Pipe()
		conn := &stubTCPConn{
			Conn: tunnel,
			id: &stack.TransportEndpointID{
				RemoteAddress: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}),
				RemotePort:    srcPort,
				LocalAddress:  tcpip.AddrFrom4(dstIP),
				LocalPort:     443,
			},
		}
		done := make(chan struct{})
		go func() {
			handler.handleTCP(conn)
			close(done)
		}()
		if _, err := client.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(client, buf); err != nil {
			t.Fatal(err)
		}
		if string(buf) != payload {
			t.Fatalf("回显不一致：%q", buf)
		}
		_ = client.Close()
		<-done
	}

	// 1. Edge 走 SSH 并计入流量；Antigravity 的子进程 language_server.exe 通过父进程命中也走 SSH；Firefox 走直连，不计入 SSH 流量。
	sendAndEcho(51001, [4]byte{198, 19, 0, 10}, "EDGE-SSH")
	sendAndEcho(51003, [4]byte{198, 19, 0, 10}, "CHILD-SSH")
	sendAndEcho(51002, [4]byte{198, 19, 0, 20}, "FIREFOX-DIRECT-PAYLOAD")

	sshMu.Lock()
	gotSSH := append([]string(nil), sshDialed...)
	sshMu.Unlock()
	if len(gotSSH) != 2 || gotSSH[0] != "edge.test:443" || gotSSH[1] != "edge.test:443" {
		t.Fatalf("SSH 拨号目标 = %v，期望 [edge.test:443 edge.test:443]", gotSSH)
	}
	direct.mu.Lock()
	gotDirect := append([]string(nil), direct.dialed...)
	direct.mu.Unlock()
	if len(gotDirect) != 1 || gotDirect[0] != "110.242.68.66:443" {
		t.Fatalf("直连拨号目标 = %v，期望 [110.242.68.66:443]", gotDirect)
	}
	up, down := traffic.Snapshot()
	wantSSHBytes := uint64(len("EDGE-SSH") + len("CHILD-SSH"))
	if up != wantSSHBytes || down != wantSSHBytes {
		t.Fatalf("SSH 流量统计 = %d/%d，期望 %d 字节", up, down, wantSSHBytes)
	}

	// 2. 热更新规则改为仅代理 firefox.exe，验证分流方向立刻切换。
	handler.SetProcessRules([]config.ProcessRule{{Name: "firefox.exe"}})
	sendAndEcho(51001, [4]byte{198, 19, 0, 10}, "EDGE-NOW-DIRECT")
	sendAndEcho(51002, [4]byte{198, 19, 0, 20}, "FIREFOX-NOW-SSH")

	sshMu.Lock()
	gotSSH = append([]string(nil), sshDialed...)
	sshMu.Unlock()
	if len(gotSSH) != 3 || gotSSH[2] != "1.2.3.4:443" {
		t.Fatalf("热更新后 SSH 拨号 = %v，期望包含 1.2.3.4:443", gotSSH)
	}
	direct.mu.Lock()
	gotDirect = append([]string(nil), direct.dialed...)
	direct.mu.Unlock()
	if len(gotDirect) != 2 || gotDirect[1] != "110.242.68.77:443" {
		t.Fatalf("热更新后直连拨号 = %v，期望包含 110.242.68.77:443", gotDirect)
	}
}

func TestModeProcessHandlesUDPDirectAndBlocksWhitelisted(t *testing.T) {
	lookup := &stubProcessLookup{
		udp: map[uint16]ProcessIdentity{
			52001: {
				PID:   1001,
				Path:  `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
				Paths: []string{`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`},
			},
			52002: {
				PID:   1002,
				Path:  `C:\Program Files\Mozilla Firefox\firefox.exe`,
				Paths: []string{`C:\Program Files\Mozilla Firefox\firefox.exe`},
			},
		},
	}

	remoteUDP := newPipeUDPConn(&stack.TransportEndpointID{RemotePort: 443})
	direct := &stubDirectTransport{
		resolved: map[string]netip.Addr{
			"quic.firefox.test": netip.MustParseAddr("110.242.68.88"),
		},
		onListenUDP: func(bool) (net.PacketConn, error) {
			return remoteUDP, nil
		},
	}

	handler := newFastTransportHandlerWithConfig(fastTransportConfig{
		dialer: dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("按进程分流 UDP 不应拨号 SSH")
			return nil, nil
		}),
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		mode:         config.ModeProcess,
		processRules: []config.ProcessRule{{Name: "msedge.exe"}},
		lookup:       lookup,
		direct:       direct,
	})
	handler.transport.dnsNames.store("quic.firefox.test", netip.MustParseAddr("198.19.0.30"), time.Minute)

	// 1. 白名单进程（Edge）的非 DNS UDP 应被阻止，且不打开直连 UDP。
	edgeUDP := newPipeUDPConn(&stack.TransportEndpointID{
		RemoteAddress: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}),
		RemotePort:    52001,
		LocalAddress:  tcpip.AddrFrom4([4]byte{203, 0, 113, 9}),
		LocalPort:     443,
	})
	handler.handleUDP(edgeUDP)
	direct.mu.Lock()
	calls := direct.listenCalled
	direct.mu.Unlock()
	if calls != 0 {
		t.Fatalf("白名单进程的 UDP 不应打开直连套接字，实际调用 %d 次", calls)
	}

	// 2. 非白名单进程（Firefox）的 Fake-IP UDP 应通过直连套接字发向真实 IP 并回传响应。
	ffUDP := newPipeUDPConn(&stack.TransportEndpointID{
		RemoteAddress: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}),
		RemotePort:    52002,
		LocalAddress:  tcpip.AddrFrom4([4]byte{198, 19, 0, 30}),
		LocalPort:     443,
	})
	done := make(chan struct{})
	go func() {
		handler.handleUDP(ffUDP)
		close(done)
	}()

	ffUDP.in <- []byte("QUIC-HELLO")
	select {
	case pkt := <-remoteUDP.out:
		if string(pkt.data) != "QUIC-HELLO" {
			t.Fatalf("直连 UDP 上行内容 = %q", pkt.data)
		}
		if pkt.addr.String() != "110.242.68.88:443" {
			t.Fatalf("直连 UDP 目标地址 = %q，期望 110.242.68.88:443", pkt.addr.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("等待直连 UDP 上行超时")
	}

	remoteUDP.in <- []byte("QUIC-REPLY")
	select {
	case pkt := <-ffUDP.out:
		if string(pkt.data) != "QUIC-REPLY" {
			t.Fatalf("直连 UDP 下行内容 = %q", pkt.data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("等待直连 UDP 下行超时")
	}

	_ = ffUDP.Close()
	<-done
}

func openActiveEchoTCP(t *testing.T, handler *fastTransportHandler, srcPort uint16, dstIP [4]byte, initPayload string) (net.Conn, chan struct{}) {
	t.Helper()
	client, tunnel := net.Pipe()
	conn := &stubTCPConn{
		Conn: tunnel,
		id: &stack.TransportEndpointID{
			RemoteAddress: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}),
			RemotePort:    srcPort,
			LocalAddress:  tcpip.AddrFrom4(dstIP),
			LocalPort:     443,
		},
	}
	done := make(chan struct{})
	go func() {
		handler.handleTCP(conn)
		close(done)
	}()
	if _, err := client.Write([]byte(initPayload)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(initPayload))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != initPayload {
		t.Fatalf("初始回显不一致：%q", buf)
	}
	return client, done
}

func assertFlowClosed(t *testing.T, client net.Conn, done <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s 未在规则变更后立即断开", label)
	}
	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var one [1]byte
	if _, err := client.Read(one[:]); err == nil {
		t.Fatalf("%s 客户端连接理应已关闭", label)
	}
	_ = client.Close()
}

func TestSetProcessRulesClosesFlippedTCPFlowsOnly(t *testing.T) {
	var sshMu sync.Mutex
	var sshDialed []string

	lookup := &stubProcessLookup{
		tcp: map[uint16]ProcessIdentity{
			51001: {
				PID:   1001,
				Path:  `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
				Paths: []string{`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`},
			},
			51002: {
				PID:   1002,
				Path:  `C:\Program Files\Mozilla Firefox\firefox.exe`,
				Paths: []string{`C:\Program Files\Mozilla Firefox\firefox.exe`},
			},
			51003: {
				PID:   1003,
				Path:  `C:\Windows\System32\svchost.exe`,
				Paths: []string{`C:\Windows\System32\svchost.exe`},
			},
		},
	}
	direct := &stubDirectTransport{
		resolved: map[string]netip.Addr{
			"edge.test":    netip.MustParseAddr("110.242.68.10"),
			"firefox.test": netip.MustParseAddr("110.242.68.20"),
			"svc.test":     netip.MustParseAddr("110.242.68.30"),
		},
		onDialTCP: func(context.Context, string) (net.Conn, error) {
			return startEchoPipe(), nil
		},
	}

	handler := newFastTransportHandlerWithConfig(fastTransportConfig{
		dialer: dialerFunc(func(_ context.Context, _, address string) (net.Conn, error) {
			sshMu.Lock()
			sshDialed = append(sshDialed, address)
			sshMu.Unlock()
			return startEchoPipe(), nil
		}),
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		mode:         config.ModeProcess,
		processRules: []config.ProcessRule{{Name: "msedge.exe"}},
		lookup:       lookup,
		direct:       direct,
	})
	defer handler.Close()

	handler.transport.dnsNames.store("edge.test", netip.MustParseAddr("198.19.0.10"), time.Minute)
	handler.transport.dnsNames.store("firefox.test", netip.MustParseAddr("198.19.0.20"), time.Minute)
	handler.transport.dnsNames.store("svc.test", netip.MustParseAddr("198.19.0.30"), time.Minute)

	// 建立三条持久活动连接：Edge(SSH)、Firefox(直连)、Svchost(直连)。
	edgeClient, edgeDone := openActiveEchoTCP(t, handler, 51001, [4]byte{198, 19, 0, 10}, "EDGE-1")
	ffClient, ffDone := openActiveEchoTCP(t, handler, 51002, [4]byte{198, 19, 0, 20}, "FF-1")
	svcClient, svcDone := openActiveEchoTCP(t, handler, 51003, [4]byte{198, 19, 0, 30}, "SVC-1")

	// 规则切换为仅代理 firefox.exe：Edge(SSH->直连) 和 Firefox(直连->SSH) 应立即断开，Svchost(直连->直连) 保持不断。
	closed := handler.SetProcessRules([]config.ProcessRule{{Name: "firefox.exe"}})
	if closed != 2 {
		t.Fatalf("规则切换返回断开连接数 = %d，期望 2", closed)
	}
	assertFlowClosed(t, edgeClient, edgeDone, "Edge 活动连接")
	assertFlowClosed(t, ffClient, ffDone, "Firefox 活动连接")

	select {
	case <-svcDone:
		t.Fatal("未受规则影响的 Svchost 活动连接不应被断开")
	default:
	}
	if _, err := svcClient.Write([]byte("SVC-2")); err != nil {
		t.Fatalf("Svchost 写入失败：%v", err)
	}
	svcBuf := make([]byte, len("SVC-2"))
	if _, err := io.ReadFull(svcClient, svcBuf); err != nil || string(svcBuf) != "SVC-2" {
		t.Fatalf("Svchost 未受影响连接回显异常：buf=%q err=%v", svcBuf, err)
	}
	_ = svcClient.Close()
	<-svcDone

	// 新建连接立刻沿新路由生效：Edge 走直连，Firefox 走 SSH。
	edgeNew, edgeNewDone := openActiveEchoTCP(t, handler, 51001, [4]byte{198, 19, 0, 10}, "EDGE-NEW")
	ffNew, ffNewDone := openActiveEchoTCP(t, handler, 51002, [4]byte{198, 19, 0, 20}, "FF-NEW")
	_ = edgeNew.Close()
	_ = ffNew.Close()
	<-edgeNewDone
	<-ffNewDone

	sshMu.Lock()
	gotSSH := append([]string(nil), sshDialed...)
	sshMu.Unlock()
	if len(gotSSH) != 2 || gotSSH[0] != "edge.test:443" || gotSSH[1] != "firefox.test:443" {
		t.Fatalf("SSH 拨号序列 = %v，期望 [edge.test:443 firefox.test:443]", gotSSH)
	}
	direct.mu.Lock()
	gotDirect := append([]string(nil), direct.dialed...)
	direct.mu.Unlock()
	if len(gotDirect) != 3 || gotDirect[2] != "110.242.68.10:443" {
		t.Fatalf("直连拨号序列 = %v，期望第 3 条为 110.242.68.10:443", gotDirect)
	}
}

func TestSetProcessRulesClosesChildProcessFlowsWhenParentToggled(t *testing.T) {
	const (
		antigravityPath = `C:\Users\11750\AppData\Local\Programs\antigravity\Antigravity.exe`
		childPath       = `C:\Users\11750\AppData\Local\Programs\antigravity\resources\bin\language_server.exe`
	)

	var sshCount int
	var sshMu sync.Mutex
	lookup := &stubProcessLookup{
		tcp: map[uint16]ProcessIdentity{
			51003: {
				PID:   1003,
				Path:  childPath,
				Paths: []string{childPath, antigravityPath},
			},
		},
	}
	direct := &stubDirectTransport{
		resolved: map[string]netip.Addr{
			"api.test": netip.MustParseAddr("110.242.68.99"),
		},
		onDialTCP: func(context.Context, string) (net.Conn, error) {
			return startEchoPipe(), nil
		},
	}

	handler := newFastTransportHandlerWithConfig(fastTransportConfig{
		dialer: dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			sshMu.Lock()
			sshCount++
			sshMu.Unlock()
			return startEchoPipe(), nil
		}),
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		mode:         config.ModeProcess,
		processRules: nil,
		lookup:       lookup,
		direct:       direct,
	})
	defer handler.Close()
	handler.transport.dnsNames.store("api.test", netip.MustParseAddr("198.19.0.55"), time.Minute)

	// 1. 初始白名单为空，子进程 language_server.exe 先建立直连长连接。
	c1, d1 := openActiveEchoTCP(t, handler, 51003, [4]byte{198, 19, 0, 55}, "INIT")

	// 动态添加父进程 Antigravity.exe：应立即断开该直连子进程连接。
	closed := handler.SetProcessRules([]config.ProcessRule{{Name: "Antigravity", Path: antigravityPath}})
	if closed != 1 {
		t.Fatalf("新增父进程规则断开数 = %d，期望 1", closed)
	}
	assertFlowClosed(t, c1, d1, "子进程直连长连接")

	// 2. 新建连接经 SSH 建立。
	c2, d2 := openActiveEchoTCP(t, handler, 51003, [4]byte{198, 19, 0, 55}, "VIA-SSH")
	sshMu.Lock()
	gotSSH := sshCount
	sshMu.Unlock()
	if gotSSH != 1 {
		t.Fatalf("预期新增父进程规则后子进程走 SSH，实际 SSH 拨号次数 = %d", gotSSH)
	}

	// 动态取消勾选父进程规则（enabled: false）：应立即断开子进程的 SSH 连接。
	disabled := false
	closed = handler.SetProcessRules([]config.ProcessRule{{
		Name:    "Antigravity",
		Path:    antigravityPath,
		Enabled: &disabled,
	}})
	if closed != 1 {
		t.Fatalf("停用父进程规则断开数 = %d，期望 1", closed)
	}
	assertFlowClosed(t, c2, d2, "子进程 SSH 长连接")
}

func TestSetProcessRulesCancelsInFlightDirectDial(t *testing.T) {
	const (
		antigravityPath = `C:\Users\11750\AppData\Local\Programs\antigravity\Antigravity.exe`
		childPath       = `C:\Users\11750\AppData\Local\Programs\antigravity\resources\bin\language_server.exe`
	)

	dialEntered := make(chan struct{})
	dialCanceled := make(chan struct{})
	lookup := &stubProcessLookup{
		tcp: map[uint16]ProcessIdentity{
			51004: {
				PID:   1004,
				Path:  childPath,
				Paths: []string{childPath, antigravityPath},
			},
		},
	}
	direct := &stubDirectTransport{
		onDialTCP: func(ctx context.Context, _ string) (net.Conn, error) {
			close(dialEntered)
			<-ctx.Done()
			close(dialCanceled)
			return nil, ctx.Err()
		},
	}

	handler := newFastTransportHandlerWithConfig(fastTransportConfig{
		dialer: dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			return startEchoPipe(), nil
		}),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		mode:   config.ModeProcess,
		lookup: lookup,
		direct: direct,
	})
	defer handler.Close()

	client, tunnel := net.Pipe()
	defer client.Close()
	conn := &stubTCPConn{
		Conn: tunnel,
		id: &stack.TransportEndpointID{
			RemoteAddress: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}),
			RemotePort:    51004,
			LocalAddress:  tcpip.AddrFrom4([4]byte{172, 217, 114, 4}),
			LocalPort:     443,
		},
	}
	done := make(chan struct{})
	go func() {
		handler.handleTCP(conn)
		close(done)
	}()

	<-dialEntered
	closed := handler.SetProcessRules([]config.ProcessRule{{Name: "Antigravity", Path: antigravityPath}})
	if closed != 1 {
		t.Fatalf("取消阻塞直连拨号断开数 = %d，期望 1", closed)
	}
	select {
	case <-dialCanceled:
	case <-time.After(2 * time.Second):
		t.Fatal("规则变更后未立即取消正在阻塞的直连拨号")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("阻塞拨号取消后 handleTCP 未及时退出")
	}
}

func TestSetProcessRulesClosesFlippedDirectUDPFlow(t *testing.T) {
	lookup := &stubProcessLookup{
		udp: map[uint16]ProcessIdentity{
			52001: {
				PID:   1001,
				Path:  `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
				Paths: []string{`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`},
			},
		},
	}
	remoteUDP := newPipeUDPConn(&stack.TransportEndpointID{RemotePort: 443})
	direct := &stubDirectTransport{
		resolved: map[string]netip.Addr{
			"quic.edge.test": netip.MustParseAddr("110.242.68.88"),
		},
		onListenUDP: func(bool) (net.PacketConn, error) {
			return remoteUDP, nil
		},
	}

	handler := newFastTransportHandlerWithConfig(fastTransportConfig{
		dialer: dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("按进程分流 UDP 不应拨号 SSH")
			return nil, nil
		}),
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		mode:         config.ModeProcess,
		processRules: nil,
		lookup:       lookup,
		direct:       direct,
	})
	defer handler.Close()
	handler.transport.dnsNames.store("quic.edge.test", netip.MustParseAddr("198.19.0.30"), time.Minute)

	edgeUDP := newPipeUDPConn(&stack.TransportEndpointID{
		RemoteAddress: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}),
		RemotePort:    52001,
		LocalAddress:  tcpip.AddrFrom4([4]byte{198, 19, 0, 30}),
		LocalPort:     443,
	})
	done := make(chan struct{})
	go func() {
		handler.handleUDP(edgeUDP)
		close(done)
	}()

	edgeUDP.in <- []byte("QUIC-PING")
	select {
	case <-remoteUDP.out:
	case <-time.After(2 * time.Second):
		t.Fatal("等待直连 UDP 上行超时")
	}

	closed := handler.SetProcessRules([]config.ProcessRule{{Name: "msedge.exe"}})
	if closed != 1 {
		t.Fatalf("启用 Edge 规则时断开直连 UDP 数 = %d，期望 1", closed)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("规则启用后活动直连 UDP 会话未立即关闭")
	}
}

func TestCloseCancelsInFlightDialImmediately(t *testing.T) {
	dialEntered := make(chan struct{})
	lookup := &stubProcessLookup{
		tcp: map[uint16]ProcessIdentity{
			51005: {
				PID:   1005,
				Path:  `C:\Windows\System32\curl.exe`,
				Paths: []string{`C:\Windows\System32\curl.exe`},
			},
		},
	}
	direct := &stubDirectTransport{
		onDialTCP: func(ctx context.Context, _ string) (net.Conn, error) {
			close(dialEntered)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	handler := newFastTransportHandlerWithConfig(fastTransportConfig{
		dialer: dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, context.Canceled
		}),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		mode:   config.ModeProcess,
		lookup: lookup,
		direct: direct,
	})

	client, tunnel := net.Pipe()
	defer client.Close()
	conn := &stubTCPConn{
		Conn: tunnel,
		id: &stack.TransportEndpointID{
			RemoteAddress: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}),
			RemotePort:    51005,
			LocalAddress:  tcpip.AddrFrom4([4]byte{203, 0, 113, 9}),
			LocalPort:     443,
		},
	}
	handler.HandleTCP(conn)
	<-dialEntered

	closeDone := make(chan struct{})
	go func() {
		handler.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(1 * time.Second):
		t.Fatal("Close() 未能立即取消阻塞中的拨号并退出")
	}
}
