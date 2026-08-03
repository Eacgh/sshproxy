package globalproxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
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
		handler.relayTCP(originTunnel, remoteTunnel)
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
