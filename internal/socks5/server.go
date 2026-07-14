package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	version5                = 0x05
	methodNoAuth            = 0x00
	methodRejected          = 0xff
	commandConnect          = 0x01
	addressIPv4             = 0x01
	addressDomain           = 0x03
	addressIPv6             = 0x04
	replySucceeded          = 0x00
	replyGeneral            = 0x01
	replyNotAllowed         = 0x02
	replyNetUnreach         = 0x03
	replyHostUnreach        = 0x04
	replyConnRefused        = 0x05
	replyCommandUnsupported = 0x07
	replyAddressUnsupported = 0x08
)

// Dialer 抽象目标连接方式；正式运行时由 SSH Manager 实现。
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Server 实现 RFC 1928 中无需认证的 CONNECT 子集。
type Server struct {
	listenAddr  string
	dialTimeout time.Duration
	dialer      Dialer
	logger      *slog.Logger

	mu       sync.Mutex
	listener net.Listener
	clients  map[net.Conn]struct{}
	closed   bool
	wg       sync.WaitGroup
}

// New 创建只允许绑定到本机回环地址的 SOCKS5 服务。
func New(listenAddr string, dialTimeout time.Duration, dialer Dialer, logger *slog.Logger) (*Server, error) {
	if err := ValidateListenAddress(listenAddr); err != nil {
		return nil, err
	}
	if dialTimeout <= 0 {
		return nil, errors.New("连接超时时间必须大于零")
	}
	if dialer == nil {
		return nil, errors.New("未提供目标连接器")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		listenAddr: listenAddr, dialTimeout: dialTimeout, dialer: dialer,
		logger: logger, clients: make(map[net.Conn]struct{}),
	}, nil
}

// ValidateListenAddress 防止无认证代理被意外暴露到局域网或公网。
func ValidateListenAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("SOCKS5 监听地址无效，必须采用 IP:端口 格式")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("SOCKS5 服务必须监听数字形式的回环地址")
	}
	return nil
}

// ListenAndServe 创建 TCP 监听器并开始处理 SOCKS5 请求。
func (s *Server) ListenAndServe(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("监听 SOCKS5 连接失败：%w", err)
	}
	return s.Serve(ctx, listener)
}

// Serve 使用已有监听器提供服务，便于测试和外部控制端口生命周期。
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		listener.Close()
		return net.ErrClosed
	}
	if s.listener != nil {
		s.mu.Unlock()
		listener.Close()
		return errors.New("SOCKS5 服务已经在运行")
	}
	s.listener = listener
	s.mu.Unlock()

	s.logger.Info("SOCKS5 代理已开始监听", "地址", listener.Addr().String())
	go func() {
		<-ctx.Done()
		s.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				s.wg.Wait()
				return nil
			}
			return fmt.Errorf("接收 SOCKS5 连接失败：%w", err)
		}
		if !s.track(conn) {
			conn.Close()
			continue
		}
		go s.handle(conn)
	}
}

func (s *Server) track(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.clients[conn] = struct{}{}
	s.wg.Add(1)
	return true
}

func (s *Server) handle(client net.Conn) {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		delete(s.clients, client)
		s.mu.Unlock()
		client.Close()
	}()

	// 协商阶段设置期限，避免客户端连接后不发送完整请求而长期占用资源。
	if err := client.SetDeadline(time.Now().Add(s.dialTimeout)); err != nil {
		return
	}
	if err := negotiate(client); err != nil {
		s.logger.Debug("SOCKS5 协商失败", "客户端", client.RemoteAddr(), "错误", err)
		return
	}
	target, replyCode, err := readRequest(client)
	if err != nil {
		if replyCode != 0 {
			writeReply(client, replyCode)
		}
		s.logger.Debug("收到无效的 SOCKS5 请求", "客户端", client.RemoteAddr(), "错误", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout)
	remote, err := s.dialer.DialContext(ctx, "tcp", target)
	cancel()
	if err != nil {
		writeReply(client, classifyDialError(err))
		s.logger.Debug("SOCKS5 目标连接失败", "目标", target, "错误", err)
		return
	}
	defer remote.Close()
	if err := writeReply(client, replySucceeded); err != nil {
		return
	}
	if err := client.SetDeadline(time.Time{}); err != nil {
		return
	}
	s.logger.Debug("SOCKS5 隧道已建立", "目标", target)
	proxy(client, remote)
}

func negotiate(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != version5 {
		return fmt.Errorf("不支持 SOCKS 版本 %d", header[0])
	}
	if header[1] == 0 {
		return errors.New("客户端没有提供认证方式")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	for _, method := range methods {
		if method == methodNoAuth {
			_, err := conn.Write([]byte{version5, methodNoAuth})
			return err
		}
	}
	_, err := conn.Write([]byte{version5, methodRejected})
	if err != nil {
		return err
	}
	return errors.New("客户端不支持无认证模式")
}

// readRequest 仅接受 CONNECT 命令，并保留域名让 SSH 服务器端解析。
func readRequest(conn net.Conn) (string, byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, err
	}
	if header[0] != version5 {
		return "", replyGeneral, fmt.Errorf("不支持 SOCKS 版本 %d", header[0])
	}
	if header[1] != commandConnect {
		return "", replyCommandUnsupported, fmt.Errorf("不支持 SOCKS 命令 %d", header[1])
	}
	if header[2] != 0 {
		return "", replyGeneral, errors.New("SOCKS5 请求的保留字节必须为零")
	}

	var host string
	switch header[3] {
	case addressIPv4:
		value := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, value); err != nil {
			return "", 0, err
		}
		host = net.IP(value).String()
	case addressIPv6:
		value := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, value); err != nil {
			return "", 0, err
		}
		host = net.IP(value).String()
	case addressDomain:
		length := []byte{0}
		if _, err := io.ReadFull(conn, length); err != nil {
			return "", 0, err
		}
		if length[0] == 0 {
			return "", replyAddressUnsupported, errors.New("目标域名不能为空")
		}
		value := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, value); err != nil {
			return "", 0, err
		}
		host = string(value)
	default:
		return "", replyAddressUnsupported, fmt.Errorf("不支持地址类型 %d", header[3])
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", 0, err
	}
	port := binary.BigEndian.Uint16(portBytes)
	if port == 0 {
		return "", replyAddressUnsupported, errors.New("目标端口不能为零")
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), 0, nil
}

func writeReply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{version5, code, 0x00, addressIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	return err
}

func classifyDialError(err error) byte {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return replyHostUnreach
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Timeout() {
			return replyHostUnreach
		}
		return replyConnRefused
	}
	return replyGeneral
}

// proxy 同时复制两个方向的数据，并在单向结束时发送半关闭信号。
func proxy(client, remote net.Conn) {
	done := make(chan struct{}, 2)
	copyOneWay := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		// 半关闭允许对端在请求体结束后继续返回剩余响应数据。
		if closeWriter, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyOneWay(remote, client)
	go copyOneWay(client, remote)
	<-done
	<-done
}

// Close 停止监听并关闭所有仍在处理的客户端连接。
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	listener := s.listener
	clients := make([]net.Conn, 0, len(s.clients))
	for client := range s.clients {
		clients = append(clients, client)
	}
	s.mu.Unlock()

	if listener != nil {
		listener.Close()
	}
	for _, client := range clients {
		client.Close()
	}
	return nil
}
