package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"sshvpn/internal/config"
)

func TestManagerDialsThroughSSHDirectTCPIP(t *testing.T) {
	configRoot := useTemporaryConfigDir(t)
	target := startEchoServer(t)
	sshAddress := startSSHServer(t, "test-password")

	cfg := config.Config{
		ServerAddress: sshAddress,
		Username:      "test-user",
		Password:      "test-password",
		ProxyPort:     1080,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := NewManager(cfg, logger)
	if err != nil {
		t.Fatalf("NewManager() 返回错误：%v", err)
	}
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := manager.Connect(ctx); err != nil {
		t.Fatalf("Connect() 返回错误：%v", err)
	}
	knownHosts, err := os.ReadFile(filepath.Join(configRoot, "sshvpn", "known_hosts"))
	if err != nil || len(knownHosts) == 0 {
		t.Fatalf("首次连接没有自动保存主机密钥：%v", err)
	}

	conn, err := manager.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatalf("DialContext() 返回错误：%v", err)
	}
	defer conn.Close()
	payload := []byte("through-ssh")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("收到 %q，期望 %q", got, payload)
	}
}

func TestHostKeyChangeIsRejected(t *testing.T) {
	useTemporaryConfigDir(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	callback, err := buildHostKeyCallback(logger)
	if err != nil {
		t.Fatal(err)
	}
	first := generateSigner(t)
	second := generateSigner(t)
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	if err := callback("example.com:22", remote, first.PublicKey()); err != nil {
		t.Fatalf("首次记录主机密钥失败：%v", err)
	}
	if err := callback("example.com:22", remote, second.PublicKey()); err == nil || !strings.Contains(err.Error(), "发生变化") {
		t.Fatalf("主机密钥变化未被拒绝：%v", err)
	}
}

func useTemporaryConfigDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	previous := userConfigDir
	userConfigDir = func() (string, error) { return root, nil }
	t.Cleanup(func() { userConfigDir = previous })
	return root
}

func generateSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func startEchoServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

func startSSHServer(t *testing.T, password string) string {
	t.Helper()
	signer := generateSigner(t)
	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(metadata ssh.ConnMetadata, supplied []byte) (*ssh.Permissions, error) {
			if metadata.User() != "test-user" || string(supplied) != password {
				return nil, fmt.Errorf("认证被拒绝")
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serveSSHConnection(conn, serverConfig)
		}
	}()
	return listener.Addr().String()
}

func serveSSHConnection(conn net.Conn, serverConfig *ssh.ServerConfig) {
	serverConn, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
	if err != nil {
		conn.Close()
		return
	}
	defer serverConn.Close()
	go ssh.DiscardRequests(requests)
	for newChannel := range channels {
		go handleDirectTCPIP(newChannel)
	}
}

func handleDirectTCPIP(newChannel ssh.NewChannel) {
	if newChannel.ChannelType() != "direct-tcpip" {
		_ = newChannel.Reject(ssh.UnknownChannelType, "不支持此通道类型")
		return
	}
	var request struct {
		DestinationAddress string
		DestinationPort    uint32
		OriginAddress      string
		OriginPort         uint32
	}
	if err := ssh.Unmarshal(newChannel.ExtraData(), &request); err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "direct-tcpip 请求无效")
		return
	}
	target := net.JoinHostPort(request.DestinationAddress, strconv.Itoa(int(request.DestinationPort)))
	remote, err := net.DialTimeout("tcp", target, time.Second)
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		remote.Close()
		return
	}
	go ssh.DiscardRequests(requests)
	go func() {
		defer channel.Close()
		defer remote.Close()
		_, _ = io.Copy(channel, remote)
	}()
	go func() {
		_, _ = io.Copy(remote, channel)
		if tcpConn, ok := remote.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}()
}
