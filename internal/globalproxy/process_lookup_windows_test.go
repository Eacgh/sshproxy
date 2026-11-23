//go:build windows

package globalproxy

import (
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestWindowsProcessLookupFindsOwnTCPAndUDPSockets(t *testing.T) {
	selfExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	selfPID := uint32(os.Getpid())
	lookup := newWindowsProcessLookup()

	// 1. 验证真实 TCP 连接的反查（四元组 + 字节序 + 父进程祖先链）。
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	client, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	serverConn := <-accepted
	defer serverConn.Close()

	localAddr := client.LocalAddr().(*net.TCPAddr)
	remoteAddr := client.RemoteAddr().(*net.TCPAddr)
	srcIP, _ := netip.AddrFromSlice(localAddr.IP)
	dstIP, _ := netip.AddrFromSlice(remoteAddr.IP)

	id, ok := lookup.LookupTCP(srcIP, uint16(localAddr.Port), dstIP, uint16(remoteAddr.Port))
	if !ok || id.PID != selfPID {
		t.Fatalf("LookupTCP = (pid=%d, path=%q, ok=%v)，期望 selfPID=%d", id.PID, id.Path, ok, selfPID)
	}
	if !strings.EqualFold(id.Path, selfExe) {
		t.Fatalf("LookupTCP 进程路径 = %q，期望 %q", id.Path, selfExe)
	}
	if len(id.Paths) < 2 {
		t.Fatalf("LookupTCP 未沿父进程链追溯到祖先进程：%v", id.Paths)
	}

	// 2. 验证真实 UDP 套接字的反查。
	udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	udpAddr := udpConn.LocalAddr().(*net.UDPAddr)
	udpIP, _ := netip.AddrFromSlice(udpAddr.IP)

	uID, uOK := lookup.LookupUDP(udpIP, uint16(udpAddr.Port))
	if !uOK || uID.PID != selfPID {
		t.Fatalf("LookupUDP = (pid=%d, path=%q, ok=%v)，期望 selfPID=%d", uID.PID, uID.Path, uOK, selfPID)
	}
	if !strings.EqualFold(uID.Path, selfExe) {
		t.Fatalf("LookupUDP 进程路径 = %q，期望 %q", uID.Path, selfExe)
	}
}

func TestListRunningProcessesReturnsActiveProcesses(t *testing.T) {
	list, err := ListRunningProcesses()
	if err != nil {
		t.Fatalf("ListRunningProcesses() 失败：%v", err)
	}
	if len(list) == 0 {
		t.Fatal("ListRunningProcesses() 返回空列表")
	}
	for _, item := range list {
		if item.Name == "" || item.Path == "" {
			t.Fatalf("进程条目存在空字段：%+v", item)
		}
	}
}
