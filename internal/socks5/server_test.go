package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

type recordingDialer struct {
	mu      sync.Mutex
	targets []string
	dialer  net.Dialer
}

func (d *recordingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.targets = append(d.targets, address)
	d.mu.Unlock()
	return d.dialer.DialContext(ctx, network, address)
}

func (d *recordingDialer) lastTarget() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.targets) == 0 {
		return ""
	}
	return d.targets[len(d.targets)-1]
}

func TestServerConnectsAndProxiesDomainTarget(t *testing.T) {
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetListener.Close()
	go func() {
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dialer := &recordingDialer{}
	server, err := New("127.0.0.1:1080", 2*time.Second, dialer, nil)
	if err != nil {
		t.Fatalf("创建 SOCKS5 服务失败：%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx, proxyListener) }()

	client, err := net.Dial("tcp", proxyListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte{version5, 1, methodNoAuth}); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if response[0] != version5 || response[1] != methodNoAuth {
		t.Fatalf("协商响应为 %v", response)
	}

	_, portText, err := net.SplitHostPort(targetListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	domain := "localhost"
	request := []byte{version5, commandConnect, 0, addressDomain, byte(len(domain))}
	request = append(request, domain...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	request = append(request, portBytes...)
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != replySucceeded {
		t.Fatalf("CONNECT 响应码为 %d", reply[1])
	}

	payload := []byte("through-the-proxy")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("代理返回 %q，期望 %q", got, payload)
	}
	if gotTarget := dialer.lastTarget(); gotTarget != net.JoinHostPort(domain, portText) {
		t.Fatalf("实际连接目标为 %q", gotTarget)
	}

	client.Close()
	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve() 返回错误：%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SOCKS5 服务未按时停止")
	}
}

func TestServerRejectsUnsupportedAuthentication(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	done := make(chan error, 1)
	go func() { done <- negotiate(serverConn) }()

	if _, err := clientConn.Write([]byte{version5, 1, 0x02}); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, response); err != nil {
		t.Fatal(err)
	}
	if response[1] != methodRejected {
		t.Fatalf("认证响应为 %v", response)
	}
	if err := <-done; err == nil {
		t.Fatal("negotiate() 意外成功，期望拒绝请求")
	}
}

func TestValidateListenAddressRejectsNonLoopback(t *testing.T) {
	for _, address := range []string{"0.0.0.0:1080", "192.168.1.2:1080", "localhost:1080"} {
		if err := ValidateListenAddress(address); err == nil {
			t.Fatalf("ValidateListenAddress(%q) 意外成功", address)
		}
	}
}
