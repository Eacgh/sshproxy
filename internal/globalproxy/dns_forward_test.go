package globalproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestCustomDNSResolverQueriesInParallel(t *testing.T) {
	name, err := dnsmessage.NewName("example.com.")
	if err != nil {
		t.Fatal(err)
	}
	queryMessage := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 42, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	query, err := queryMessage.Pack()
	if err != nil {
		t.Fatal(err)
	}
	responseMessage := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 42, Response: true, RecursionAvailable: true},
		Questions: queryMessage.Questions,
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.AResource{A: [4]byte{203, 0, 113, 8}},
		}},
	}
	response, err := responseMessage.Pack()
	if err != nil {
		t.Fatal(err)
	}

	var active atomic.Int32
	var maximum atomic.Int32
	dialer := dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go serveDelayedDNSResponse(server, response, &active, &maximum)
		return client, nil
	})
	cache := newDNSNameCache()
	resolver := newCustomDNSResolver(dialer, "9.9.9.9:53", newFakeDNSResolver(cache), cache, slog.Default())
	defer resolver.close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var wait sync.WaitGroup
	errorsSeen := make(chan error, customDNSConnections)
	for range customDNSConnections {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := resolver.resolve(ctx, query)
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := maximum.Load(); got < 2 {
		t.Fatalf("自定义 DNS 查询仍然串行执行，并发数为 %d", got)
	}
}

func TestForwardingDNSResolverReplacesIdleConnection(t *testing.T) {
	var dialCount atomic.Int32
	resolver := &forwardingDNSResolver{
		address: "9.9.9.9:53",
		dialer: dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			dialCount.Add(1)
			client, server := net.Pipe()
			go serveTestDNSConnection(server, -1)
			return client, nil
		}),
	}
	defer resolver.close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := resolver.resolve(ctx, []byte("first")); err != nil {
		t.Fatal(err)
	}
	resolver.mu.Lock()
	resolver.lastUsed = time.Now().Add(-dnsConnectionMaxIdle)
	resolver.mu.Unlock()
	if _, err := resolver.resolve(ctx, []byte("second")); err != nil {
		t.Fatal(err)
	}
	if got := dialCount.Load(); got != 2 {
		t.Fatalf("空闲 DNS 通道复用了 %d 次连接，期望主动建立第二条连接", got)
	}
}

func TestForwardingDNSResolverRetriesHungReusedConnection(t *testing.T) {
	var dialCount atomic.Int32
	resolver := &forwardingDNSResolver{
		address: "9.9.9.9:53",
		dialer: dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			attempt := dialCount.Add(1)
			client, server := net.Pipe()
			if attempt == 1 {
				go serveTestDNSConnection(server, 1)
			} else {
				go serveTestDNSConnection(server, -1)
			}
			return client, nil
		}),
	}
	defer resolver.close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := resolver.resolve(ctx, []byte("first")); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	response, err := resolver.resolve(ctx, []byte("second"))
	if err != nil {
		t.Fatalf("复用的 DNS 通道无响应后没有重新连接：%v", err)
	}
	if string(response) != "second" {
		t.Fatalf("重连后的 DNS 响应为 %q", response)
	}
	if elapsed := time.Since(started); elapsed >= 2*dnsReuseTimeout {
		t.Fatalf("DNS 重连耗时过长：%v", elapsed)
	}
	if got := dialCount.Load(); got != 2 {
		t.Fatalf("DNS 通道建立次数为 %d，期望 2", got)
	}
}

func serveTestDNSConnection(connection net.Conn, responseLimit int) {
	defer connection.Close()
	header := make([]byte, 2)
	responses := 0
	for {
		if _, err := io.ReadFull(connection, header); err != nil {
			return
		}
		length := int(binary.BigEndian.Uint16(header))
		payload := make([]byte, length)
		if _, err := io.ReadFull(connection, payload); err != nil {
			return
		}
		if responseLimit >= 0 && responses >= responseLimit {
			_, _ = connection.Read(make([]byte, 1))
			return
		}
		responses++
		binary.BigEndian.PutUint16(header, uint16(len(payload)))
		if _, err := connection.Write(append(header, payload...)); err != nil {
			return
		}
	}
}

func serveDelayedDNSResponse(connection net.Conn, response []byte, active, maximum *atomic.Int32) {
	defer connection.Close()
	header := make([]byte, 2)
	if _, err := io.ReadFull(connection, header); err != nil {
		return
	}
	payload := make([]byte, int(binary.BigEndian.Uint16(header)))
	if _, err := io.ReadFull(connection, payload); err != nil {
		return
	}
	current := active.Add(1)
	defer active.Add(-1)
	for {
		previous := maximum.Load()
		if current <= previous || maximum.CompareAndSwap(previous, current) {
			break
		}
	}
	time.Sleep(100 * time.Millisecond)
	binary.BigEndian.PutUint16(header, uint16(len(response)))
	_, _ = connection.Write(append(header, response...))
}

// TestCustomDNSFallsBackToFakeIPOnUpstreamFailure 验证自定义 DNS 不可达时
// 自动回退到 Fake-IP 解析，页面不会被卡死。
func TestCustomDNSFallsBackToFakeIPOnUpstreamFailure(t *testing.T) {
	name, err := dnsmessage.NewName("example.com.")
	if err != nil {
		t.Fatal(err)
	}
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 3},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	query, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	failing := dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("服务器无法连接自定义 DNS")
	})
	cache := newDNSNameCache()
	resolver := newCustomDNSResolver(failing, "223.5.5.5:53", newFakeDNSResolver(cache), cache, slog.Default())
	defer resolver.close()

	response, err := resolver.resolve(context.Background(), query)
	if err != nil {
		t.Fatalf("自定义 DNS 失败后应回退到 Fake-IP 而不是报错：%v", err)
	}
	var unpacked dnsmessage.Message
	if err := unpacked.Unpack(response); err != nil {
		t.Fatal(err)
	}
	if len(unpacked.Answers) != 1 {
		t.Fatalf("回退应答应为 1 条 Fake-IP 回答，实际 %d", len(unpacked.Answers))
	}
	body, ok := unpacked.Answers[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("回退应答类型为 %T", unpacked.Answers[0].Body)
	}
	address := netip.AddrFrom4(body.A)
	if !isFakeAddress(address) {
		t.Fatalf("回退应答不是 Fake-IP：%s", address)
	}
	if !resolver.unavailable.Load() {
		t.Fatal("自定义 DNS 失败后未标记为不可用")
	}
}
