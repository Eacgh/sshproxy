package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseProxyMode(t *testing.T) {
	cases := []struct {
		input string
		want  ProxyMode
		ok    bool
	}{
		{"", ModeGlobal, true},
		{"global", ModeGlobal, true},
		{"PROCESS", ModeProcess, true},
		{"socks5", ModeSOCKS5, true},
		{"unknown", "", false},
	}
	for _, tc := range cases {
		got, err := ParseProxyMode(tc.input)
		if tc.ok && (err != nil || got != tc.want) {
			t.Fatalf("ParseProxyMode(%q) = (%q, %v)，期望 %q", tc.input, got, err, tc.want)
		}
		if !tc.ok && err == nil {
			t.Fatalf("ParseProxyMode(%q) 应返回错误", tc.input)
		}
	}
}

func TestServersSaveAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")

	// 文件不存在时返回空列表。
	loaded, err := LoadServers(path)
	if err != nil || len(loaded) != 0 {
		t.Fatalf("空文件 LoadServers = (%v, %v)", loaded, err)
	}

	profiles := []ServerProfile{
		{
			Name:          "新加坡节点",
			ServerAddress: "sg.example.com",
			Username:      "root",
			Password:      "secret",
			ProxyPort:     0, // 应补全 1080
			DNSServer:     "1.1.1.1",
		},
	}
	if err := SaveServers(path, profiles); err != nil {
		t.Fatalf("SaveServers() 失败：%v", err)
	}

	loaded, err = LoadServers(path)
	if err != nil || len(loaded) != 1 {
		t.Fatalf("LoadServers() = (%v, %v)", loaded, err)
	}
	if loaded[0].ProxyPort != 1080 {
		t.Fatalf("默认代理端口应为 1080，实际 %d", loaded[0].ProxyPort)
	}

	// 重名校验。
	dup := append(loaded, loaded[0])
	if err := SaveServers(path, dup); err == nil || !strings.Contains(err.Error(), "重复") {
		t.Fatalf("重复服务器名称应报错，实际 %v", err)
	}
}

func TestMigrateFromLegacyConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	srvPath := filepath.Join(dir, "servers.json")

	if err := os.WriteFile(cfgPath, []byte(`{
		"server_address": "legacy.example.com:2222",
		"username": "alice",
		"password": "pw"
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	profiles, migrated, err := MigrateFromLegacyConfig(cfgPath, srvPath)
	if err != nil || !migrated || len(profiles) != 1 {
		t.Fatalf("MigrateFromLegacyConfig() = (%v, %v, %v)", profiles, migrated, err)
	}
	if profiles[0].Name != "legacy.example.com:2222" || profiles[0].ProxyPort != 1080 {
		t.Fatalf("迁移结果不符合预期：%+v", profiles[0])
	}

	// 二次调用不再重复迁移。
	profiles2, migrated2, err := MigrateFromLegacyConfig(cfgPath, srvPath)
	if err != nil || migrated2 || len(profiles2) != 1 {
		t.Fatalf("二次迁移 = (%v, %v, %v)", profiles2, migrated2, err)
	}
}

func TestProcessesSaveAndLoadCompatibility(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "processes.json")

	// 兼容旧版没有 enabled 字段的 processes.json。
	if err := os.WriteFile(path, []byte(`[
		{"name": "msedge", "path": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"}
	]`), 0o600); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadProcesses(path)
	if err != nil || len(rules) != 1 {
		t.Fatalf("LoadProcesses() = (%v, %v)", rules, err)
	}
	if !rules[0].IsEnabled() {
		t.Fatal("旧版缺省 enabled 字段的规则应默认启用")
	}

	disabled := false
	rules = append(rules, ProcessRule{
		Path:    `D:\Apps\curl.exe`,
		Enabled: &disabled,
	}, ProcessRule{
		Path: `D:/Apps/Antigravity/`,
	})
	if err := SaveProcesses(path, rules); err != nil {
		t.Fatalf("SaveProcesses() 失败：%v", err)
	}
	reloaded, err := LoadProcesses(path)
	if err != nil || len(reloaded) != 3 {
		t.Fatalf("SaveProcesses 后读取 = (%v, %v)", reloaded, err)
	}
	if reloaded[1].Name != "curl" || reloaded[1].IsEnabled() {
		t.Fatalf("第二条规则持久化不符合预期：%+v", reloaded[1])
	}
	if reloaded[2].Name != "Antigravity" || reloaded[2].Path != `D:\Apps\Antigravity\` {
		t.Fatalf("目录规则持久化不符合预期：%+v", reloaded[2])
	}

	// 同目标重复追加新规则（例如重新加入先前停用的程序）应覆盖启用状态，而非被旧条目吞掉。
	enabled := true
	updated := append(reloaded, ProcessRule{
		Name:    "curl",
		Path:    `D:\Apps\curl.exe`,
		Enabled: &enabled,
	})
	if err := SaveProcesses(path, updated); err != nil {
		t.Fatalf("重复更新 SaveProcesses() 失败：%v", err)
	}
	reloaded2, err := LoadProcesses(path)
	if err != nil || len(reloaded2) != 3 {
		t.Fatalf("去重更新后数量 = %d err=%v，期望 3 条", len(reloaded2), err)
	}
	if !reloaded2[1].IsEnabled() {
		t.Fatalf("重加同名规则后应恢复启用：%+v", reloaded2[1])
	}
}
