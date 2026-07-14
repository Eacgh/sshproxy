package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAppliesInternalDefaults(t *testing.T) {
	path := writeConfig(t, `{
		"server_address": "ssh.example.com",
		"username": "alice",
		"password": "secret"
	}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() 返回错误：%v", err)
	}
	if cfg.SSHAddress() != "ssh.example.com:22" {
		t.Fatalf("SSH 地址为 %q", cfg.SSHAddress())
	}
	if cfg.SOCKSListen() != "127.0.0.1:1080" {
		t.Fatalf("SOCKS5 监听地址为 %q", cfg.SOCKSListen())
	}
}

func TestLoadAcceptsCustomPorts(t *testing.T) {
	path := writeConfig(t, `{
		"server_address": "ssh.example.com:2222",
		"username": "alice",
		"password": "secret",
		"proxy_port": 2080
	}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() 返回错误：%v", err)
	}
	if cfg.SSHAddress() != "ssh.example.com:2222" || cfg.SOCKSListen() != "127.0.0.1:2080" {
		t.Fatalf("端口配置未生效：%+v", cfg)
	}
}

func TestLoadRejectsInvalidProxyPort(t *testing.T) {
	path := writeConfig(t, `{
		"server_address": "ssh.example.com",
		"username": "alice",
		"password": "secret",
		"proxy_port": 70000
	}`)

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "proxy_port") {
		t.Fatalf("Load() 返回错误：%v，期望代理端口校验错误", err)
	}
}

func TestLoadRejectsOldFields(t *testing.T) {
	path := writeConfig(t, `{"ssh": {}}`)

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "不再支持") {
		t.Fatalf("Load() 返回错误：%v，期望旧字段提示", err)
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
