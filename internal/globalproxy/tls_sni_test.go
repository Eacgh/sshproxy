package globalproxy

import (
	"crypto/tls"
	"net"
	"testing"
)

func TestSniffTLSServerNameKeepsClientHello(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	go func() {
		client := tls.Client(clientSide, &tls.Config{
			ServerName:         "x.com",
			InsecureSkipVerify: true, // 测试只生成 ClientHello，不会验证或建立真实连接。
		})
		_ = client.Handshake()
	}()

	initial, serverName, err := sniffTLSServerName(serverSide)
	if err != nil {
		t.Fatal(err)
	}
	if serverName != "x.com" {
		t.Fatalf("识别到的 TLS 域名为 %q；期望 x.com", serverName)
	}
	if len(initial) < 5 || initial[0] != 22 {
		t.Fatalf("没有保留完整的 TLS 首记录：%d 字节", len(initial))
	}
}

func TestParseTLSServerNameRejectsDamagedHello(t *testing.T) {
	if got := parseTLSServerName([]byte{1, 0, 0, 10, 3}); got != "" {
		t.Fatalf("损坏的 ClientHello 返回了域名 %q", got)
	}
}
