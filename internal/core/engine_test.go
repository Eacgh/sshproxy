package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"sshvpn/internal/config"
)

func startMockSSHForEngine(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "u" && string(pass) == "p" {
				return nil, nil
			}
			return nil, errors.New("bad password")
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					if nc.ChannelType() != "direct-tcpip" {
						_ = nc.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					ch, chReqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go ssh.DiscardRequests(chReqs)
					go func(channel ssh.Channel) {
						defer channel.Close()
						_, _ = io.Copy(channel, channel)
					}(ch)
				}
			}(raw)
		}
	}()
	return ln.Addr().String()
}

func freePortForEngine(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func TestEngineStartProxyResetAndStop(t *testing.T) {
	sshAddr := startMockSSHForEngine(t)
	socksPort := freePortForEngine(t)
	baseDir := t.TempDir()

	serversPath := filepath.Join(baseDir, "servers.json")
	if err := config.SaveServers(serversPath, []config.ServerProfile{{
		Name:          "srv1",
		ServerAddress: sshAddr,
		Username:      "u",
		Password:      "p",
		ProxyPort:     socksPort,
	}}); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var states []State
	var logs []string
	engine, err := NewEngine(baseDir, Callbacks{
		OnState: func(s StatusSnapshot) {
			mu.Lock()
			states = append(states, s.State)
			mu.Unlock()
		},
		OnLog: func(line string) {
			mu.Lock()
			logs = append(logs, line)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// 未连接时调用 UpdateProcessRules 应安全返回 (false, 0)。
	if applied, closed := engine.UpdateProcessRules([]config.ProcessRule{{Name: "msedge.exe"}}); applied || closed != 0 {
		t.Fatalf("停止状态调用 UpdateProcessRules = (%v, %d)，期望 (false, 0)", applied, closed)
	}

	if err := engine.Start(context.Background(), StartRequest{
		ServersPath: serversPath,
		ProfileName: "srv1",
		Mode:        config.ModeSOCKS5,
		Verbose:     true,
	}); err != nil {
		t.Fatalf("Engine.Start() 失败：%v", err)
	}

	// SOCKS5 拨号并回显数据。
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(conn, method[:]); err != nil || method[1] != 0x00 {
		t.Fatalf("SOCKS5 握手失败：%v %v", method, err)
	}
	host := "echo.local"
	req := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, host...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], 80)
	req = append(req, p[:]...)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || reply[1] != 0x00 {
		t.Fatalf("SOCKS5 建连失败：%v %v", reply, err)
	}

	payload := bytes.Repeat([]byte("X"), 4096)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatal("SOCKS5 回显内容不一致")
	}
	_ = conn.Close()

	snap := engine.Status()
	if snap.State != StateConnected || snap.Upload < 4096 || snap.Download < 4096 {
		t.Fatalf("状态/流量统计异常：%+v", snap)
	}

	// 运行中热重置流量。
	if err := engine.ResetTraffic(); err != nil {
		t.Fatalf("ResetTraffic() 失败：%v", err)
	}
	afterReset := engine.Status()
	if afterReset.Upload != 0 || afterReset.Download != 0 {
		t.Fatalf("重置后流量应归零，实际 %+v", afterReset)
	}

	if err := engine.Stop(); err != nil {
		t.Fatalf("Engine.Stop() 失败：%v", err)
	}
	if engine.Status().State != StateStopped {
		t.Fatalf("停止后状态应为 stopped，实际 %q", engine.Status().State)
	}

	// 验证日志文件写入且句柄已关闭（可重命名）。
	logFiles, err := filepath.Glob(filepath.Join(baseDir, "logs", "*.log"))
	if err != nil || len(logFiles) != 1 {
		t.Fatalf("日志文件数量异常：%v %v", logFiles, err)
	}
	if err := os.Rename(logFiles[0], logFiles[0]+".done"); err != nil {
		t.Fatalf("停止后重命名日志文件失败（句柄可能未关闭）：%v", err)
	}
	mu.Lock()
	hasLogs := len(logs) > 0 && strings.Contains(strings.Join(logs, "\n"), "SOCKS5")
	mu.Unlock()
	if !hasLogs {
		t.Fatalf("回调未收到预期日志：%v", logs)
	}
}
