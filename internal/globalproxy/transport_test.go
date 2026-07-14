package globalproxy

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"golang.org/x/net/dns/dnsmessage"
)

type dialerFunc func(context.Context, string, string) (net.Conn, error)

func (function dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return function(ctx, network, address)
}

func TestSSHTransportUsesDomainRestoredFromFakeIP(t *testing.T) {
	var receivedAddress string
	transport := newSSHTransport(dialerFunc(func(_ context.Context, _, address string) (net.Conn, error) {
		receivedAddress = address
		client, server := net.Pipe()
		t.Cleanup(func() { client.Close(); server.Close() })
		return client, nil
	}), "", slog.Default())

	transport.dnsNames.store("example.com", netip.MustParseAddr("198.19.0.1"), time.Minute)

	connection, err := transport.DialContext(context.Background(), &M.Metadata{
		DstIP:   netip.MustParseAddr("198.19.0.1"),
		DstPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	if receivedAddress != "example.com:443" {
		t.Fatalf("SSH 收到的目标为 %q；期望 example.com:443", receivedAddress)
	}
}

func TestSSHTransportDialsTCPThroughManager(t *testing.T) {
	var receivedAddress string
	transport := newSSHTransport(dialerFunc(func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			t.Fatalf("网络类型为 %q", network)
		}
		receivedAddress = address
		client, server := net.Pipe()
		t.Cleanup(func() { client.Close(); server.Close() })
		return client, nil
	}), "", slog.Default())

	connection, err := transport.DialContext(context.Background(), &M.Metadata{
		DstIP:   netip.MustParseAddr("203.0.113.8"),
		DstPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	if receivedAddress != "203.0.113.8:443" {
		t.Fatalf("TCP 目标为 %q", receivedAddress)
	}
}

func TestCustomDNSModeUsesResolvedIPInsteadOfSNI(t *testing.T) {
	var receivedAddress string
	transport := newSSHTransport(dialerFunc(func(_ context.Context, _, address string) (net.Conn, error) {
		receivedAddress = address
		client, server := net.Pipe()
		t.Cleanup(func() { client.Close(); server.Close() })
		return client, nil
	}), "9.9.9.9:53", slog.Default())
	transport.dnsNames.storeResolved(
		"example.com",
		netip.MustParseAddr("198.19.0.1"),
		netip.MustParseAddr("203.0.113.8"),
		time.Minute,
	)

	connection, err := transport.DialContextWithServerName(context.Background(), &M.Metadata{
		DstIP:   netip.MustParseAddr("198.19.0.1"),
		DstPort: 443,
	}, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	if receivedAddress != "203.0.113.8:443" {
		t.Fatalf("自定义 DNS 模式目标为 %q", receivedAddress)
	}
}

func TestCustomDNSIsQueriedThroughSSH(t *testing.T) {
	name, err := dnsmessage.NewName("google.com.")
	if err != nil {
		t.Fatal(err)
	}
	queryMessage := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x1234, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	query, err := queryMessage.Pack()
	if err != nil {
		t.Fatal(err)
	}
	upstreamMessage := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x1234, Response: true, RecursionAvailable: true},
		Questions: queryMessage.Questions,
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
			Body:   &dnsmessage.AResource{A: [4]byte{142, 250, 72, 14}},
		}},
	}
	upstreamResponse, err := upstreamMessage.Pack()
	if err != nil {
		t.Fatal(err)
	}
	dialer := dialerFunc(func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "9.9.9.9:53" {
			t.Fatalf("自定义 DNS 连接为 %s %s", network, address)
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			header := make([]byte, 2)
			if _, err := io.ReadFull(server, header); err != nil {
				return
			}
			payload := make([]byte, int(binary.BigEndian.Uint16(header)))
			if _, err := io.ReadFull(server, payload); err != nil || string(payload) != string(query) {
				return
			}
			binary.BigEndian.PutUint16(header, uint16(len(upstreamResponse)))
			_, _ = server.Write(append(header, upstreamResponse...))
		}()
		return client, nil
	})
	transport := newSSHTransport(dialer, "9.9.9.9:53", slog.Default())
	connection, err := transport.DialUDP(&M.Metadata{
		DstIP:   netip.MustParseAddr("192.0.2.53"),
		DstPort: 53,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	target := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 53), Port: 53}
	if _, err := connection.WriteTo(query, target); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 512)
	read, _, err := connection.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	var response dnsmessage.Message
	if err := response.Unpack(buffer[:read]); err != nil {
		t.Fatal(err)
	}
	if len(response.Answers) != 1 {
		t.Fatalf("自定义 DNS Fake-IP 回答数量为 %d", len(response.Answers))
	}
	body, ok := response.Answers[0].Body.(*dnsmessage.AResource)
	if !ok || netip.AddrFrom4(body.A).String() != "198.19.0.1" {
		t.Fatalf("自定义 DNS 返回的不是 Fake-IP：%+v", response.Answers)
	}
	if target := transport.targetAddress(&M.Metadata{
		DstIP:   netip.MustParseAddr("198.19.0.1"),
		DstPort: 443,
	}, "google.com"); target != "142.250.72.14:443" {
		t.Fatalf("Fake-IP 对应连接目标为 %q", target)
	}
}

func TestCustomDNSFiltersAAAAWithoutQueryingUpstream(t *testing.T) {
	name, err := dnsmessage.NewName("google.com.")
	if err != nil {
		t.Fatal(err)
	}
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 9},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET}},
	}
	query, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	transport := newSSHTransport(dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("AAAA 查询不应连接自定义 DNS")
		return nil, nil
	}), "9.9.9.9:53", slog.Default())
	connection, err := transport.DialUDP(&M.Metadata{
		DstIP:   netip.MustParseAddr("192.0.2.53"),
		DstPort: 53,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.WriteTo(query, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 53), Port: 53}); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 512)
	read, _, err := connection.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	var response dnsmessage.Message
	if err := response.Unpack(buffer[:read]); err != nil {
		t.Fatal(err)
	}
	if len(response.Answers) != 0 {
		t.Fatalf("AAAA 查询返回了 %d 条回答", len(response.Answers))
	}
}

func TestCustomDNSTCPAlsoFiltersAAAA(t *testing.T) {
	name, err := dnsmessage.NewName("google.com.")
	if err != nil {
		t.Fatal(err)
	}
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 10},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET}},
	}
	query, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	transport := newSSHTransport(dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("TCP AAAA 查询不应连接自定义 DNS")
		return nil, nil
	}), "9.9.9.9:53", slog.Default())
	connection, err := transport.DialContext(context.Background(), &M.Metadata{
		DstIP:   netip.MustParseAddr("192.0.2.53"),
		DstPort: 53,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, uint16(len(query)))
	if _, err := connection.Write(append(header, query...)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(connection, header); err != nil {
		t.Fatal(err)
	}
	responsePayload := make([]byte, int(binary.BigEndian.Uint16(header)))
	if _, err := io.ReadFull(connection, responsePayload); err != nil {
		t.Fatal(err)
	}
	var response dnsmessage.Message
	if err := response.Unpack(responsePayload); err != nil {
		t.Fatal(err)
	}
	if len(response.Answers) != 0 {
		t.Fatalf("TCP AAAA 查询返回了 %d 条回答", len(response.Answers))
	}
}

func TestCustomDNSFallsBackToSNIForUnknownCachedFakeIP(t *testing.T) {
	transport := newSSHTransport(dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, nil
	}), "9.9.9.9:53", slog.Default())
	target := transport.targetAddress(&M.Metadata{
		DstIP:   netip.MustParseAddr("198.19.99.99"),
		DstPort: 443,
	}, "google.com")
	if target != "google.com:443" {
		t.Fatalf("未知缓存 Fake-IP 的回退目标为 %q", target)
	}
}

func TestDNSPacketConnAnswersWithStableFakeIP(t *testing.T) {
	name, err := dnsmessage.NewName("example.com.")
	if err != nil {
		t.Fatal(err)
	}
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x1234, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	query, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	cache := newDNSNameCache()
	resolver := newFakeDNSResolver(cache)
	connection := newFakeDNSPacketConn(resolver.resolve)
	defer connection.Close()
	target := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 53), Port: 53}
	var previous netip.Addr
	for range 2 {
		if written, err := connection.WriteTo(query, target); err != nil || written != len(query) {
			t.Fatalf("WriteTo() = %d, %v", written, err)
		}
		buffer := make([]byte, 512)
		read, from, err := connection.ReadFrom(buffer)
		if err != nil {
			t.Fatal(err)
		}
		var response dnsmessage.Message
		if err := response.Unpack(buffer[:read]); err != nil {
			t.Fatal(err)
		}
		if response.Header.ID != 0x1234 || len(response.Answers) != 1 {
			t.Fatalf("Fake-IP DNS 响应无效：%+v", response)
		}
		body, ok := response.Answers[0].Body.(*dnsmessage.AResource)
		if !ok {
			t.Fatalf("DNS 响应类型为 %T", response.Answers[0].Body)
		}
		address := netip.AddrFrom4(body.A)
		if previous.IsValid() && address != previous {
			t.Fatalf("同一域名分配了不同 Fake-IP：%s、%s", previous, address)
		}
		previous = address
		if got, _, ok := cache.lookupTarget(address); !ok || got != "example.com" {
			t.Fatalf("Fake-IP 映射为 %q, %v", got, ok)
		}
		if from.String() != target.String() {
			t.Fatalf("DNS 响应地址为 %q", from)
		}
	}
	if previous.String() != "198.19.0.1" {
		t.Fatalf("第一个 Fake-IP 为 %s", previous)
	}
}

func TestFakeDNSTCPConnAnswersLocally(t *testing.T) {
	name, err := dnsmessage.NewName("example.net.")
	if err != nil {
		t.Fatal(err)
	}
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 7},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET}},
	}
	query, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	resolver := newFakeDNSResolver(newDNSNameCache())
	connection := newFakeDNSTCPConn(resolver.resolve)
	defer connection.Close()
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, uint16(len(query)))
	if _, err := connection.Write(append(header, query...)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(connection, header); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, int(binary.BigEndian.Uint16(header)))
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	var unpacked dnsmessage.Message
	if err := unpacked.Unpack(response); err != nil {
		t.Fatal(err)
	}
	if len(unpacked.Answers) != 1 {
		t.Fatalf("TCP Fake-IP DNS 回答数量为 %d", len(unpacked.Answers))
	}
}

func TestSSHTransportRejectsOrdinaryUDP(t *testing.T) {
	transport := newSSHTransport(dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("普通 UDP 不应建立 SSH TCP 通道")
		return nil, nil
	}), "", slog.New(slog.NewTextHandler(io.Discard, nil)))

	_, err := transport.DialUDP(&M.Metadata{
		DstIP:   netip.MustParseAddr("203.0.113.8"),
		DstPort: 443,
	})
	if err == nil {
		t.Fatal("普通 UDP 没有被拒绝")
	}
}
