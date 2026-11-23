package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ProxyMode 表示 SSH VPN 的流量工作模式。
type ProxyMode string

const (
	// ModeGlobal 接管整机 IPv4/IPv6 TCP 流量并经 SSH 出口，阻止非 DNS UDP。
	ModeGlobal ProxyMode = "global"
	// ModeProcess 借助 Wintun 按源端口反查进程，仅白名单进程走 SSH 出口，其余直连物理网卡。
	ModeProcess ProxyMode = "process"
	// ModeSOCKS5 仅监听本地 SOCKS5 代理端口，不安装 Wintun 或系统路由。
	ModeSOCKS5 ProxyMode = "socks5"
)

// ParseProxyMode 解析并校验模式名称；空值默认返回 ModeGlobal。
func ParseProxyMode(value string) (ProxyMode, error) {
	switch ProxyMode(strings.ToLower(strings.TrimSpace(value))) {
	case "", ModeGlobal:
		return ModeGlobal, nil
	case ModeProcess:
		return ModeProcess, nil
	case ModeSOCKS5:
		return ModeSOCKS5, nil
	default:
		return "", fmt.Errorf("不支持的代理模式 %q（可选：global、process、socks5）", value)
	}
}

// ServerProfile 对应 servers.json 中的一条服务器条目。
type ServerProfile struct {
	Name          string `json:"name"`
	ServerAddress string `json:"server_address"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	ProxyPort     int    `json:"proxy_port"`
	DNSServer     string `json:"dns_server,omitempty"`
}

// ToConfig 将服务器条目转换为校验通过的运行期 Config。
func (p ServerProfile) ToConfig() (Config, error) {
	cfg := Config{
		ServerAddress: p.ServerAddress,
		Username:      p.Username,
		Password:      p.Password,
		ProxyPort:     p.ProxyPort,
		DNSServer:     p.DNSServer,
	}
	return cfg.validateComplete()
}

// ProcessRule 对应 processes.json 中的一条按进程分流规则，向后兼容旧版字段。
type ProcessRule struct {
	Name    string `json:"name"`
	Path    string `json:"path,omitempty"`
	Args    string `json:"args,omitempty"`
	Enabled *bool  `json:"enabled,omitempty"`
}

// IsEnabled 返回该规则当前是否启用（缺省视为启用以兼容旧版 processes.json）。
func (r ProcessRule) IsEnabled() bool {
	return r.Enabled == nil || *r.Enabled
}

// MatchTarget 返回用于分流匹配的规则目标（优先路径，其次进程名）。
func (r ProcessRule) MatchTarget() string {
	if p := strings.TrimSpace(r.Path); p != "" {
		return p
	}
	return strings.TrimSpace(r.Name)
}

// LoadServers 从 servers.json 读取全部服务器条目；文件不存在时返回空列表。
func LoadServers(path string) ([]ServerProfile, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取服务器列表失败：%w", err)
	}
	var servers []ServerProfile
	if err := json.Unmarshal(data, &servers); err != nil {
		return nil, fmt.Errorf("解析服务器列表失败：%w", err)
	}
	for i := range servers {
		if servers[i].ProxyPort == 0 {
			servers[i].ProxyPort = defaultProxyPort
		}
	}
	return servers, nil
}

// SaveServers 校验并原子保存服务器列表到 servers.json。
func SaveServers(path string, profiles []ServerProfile) error {
	normalized := make([]ServerProfile, 0, len(profiles))
	seenNames := make(map[string]struct{}, len(profiles))
	for _, entry := range profiles {
		entry.Name = strings.TrimSpace(entry.Name)
		entry.ServerAddress = strings.TrimSpace(entry.ServerAddress)
		entry.Username = strings.TrimSpace(entry.Username)
		entry.DNSServer = strings.TrimSpace(entry.DNSServer)
		if entry.ProxyPort == 0 {
			entry.ProxyPort = defaultProxyPort
		}
		if entry.Name == "" {
			return errors.New("服务器名称不能为空")
		}
		if _, dup := seenNames[entry.Name]; dup {
			return fmt.Errorf("服务器名称 %q 重复，请修改后再保存", entry.Name)
		}
		seenNames[entry.Name] = struct{}{}
		if _, err := entry.ToConfig(); err != nil {
			return err
		}
		normalized = append(normalized, entry)
	}
	return writeJSONAtomic(path, normalized, "服务器列表")
}

// MigrateFromLegacyConfig 在 servers.json 尚不存在时，尝试从旧版 config.json 迁移默认条目。
func MigrateFromLegacyConfig(configPath, serversPath string) ([]ServerProfile, bool, error) {
	if _, err := os.Stat(serversPath); err == nil {
		profiles, loadErr := LoadServers(serversPath)
		return profiles, false, loadErr
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("检查服务器列表失败：%w", err)
	}

	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, fmt.Errorf("检查旧版配置文件失败：%w", err)
	}

	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, false, fmt.Errorf("读取旧版配置文件失败：%w", err)
	}
	var legacy Config
	if err := json.Unmarshal(raw, &legacy); err != nil {
		return nil, false, nil
	}
	if strings.TrimSpace(legacy.ServerAddress) == "" {
		return nil, false, nil
	}
	name := strings.TrimSpace(legacy.ServerAddress)
	if name == "" {
		name = "服务器 1"
	}
	profile := ServerProfile{
		Name:          name,
		ServerAddress: strings.TrimSpace(legacy.ServerAddress),
		Username:      strings.TrimSpace(legacy.Username),
		Password:      legacy.Password,
		ProxyPort:     legacy.ProxyPort,
		DNSServer:     strings.TrimSpace(legacy.DNSServer),
	}
	if profile.ProxyPort == 0 {
		profile.ProxyPort = defaultProxyPort
	}
	if _, err := profile.ToConfig(); err != nil {
		return nil, false, nil
	}
	profiles := []ServerProfile{profile}
	if err := SaveServers(serversPath, profiles); err != nil {
		return nil, false, err
	}
	return profiles, true, nil
}

// LoadProcesses 从 processes.json 读取进程分流规则；文件不存在时返回空列表。
func LoadProcesses(path string) ([]ProcessRule, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取进程分流列表失败：%w", err)
	}
	var rules []ProcessRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("解析进程分流列表失败：%w", err)
	}
	return rules, nil
}

// SaveProcesses 校验并原子保存进程分流规则到 processes.json。
func SaveProcesses(path string, rules []ProcessRule) error {
	normalized := make([]ProcessRule, 0, len(rules))
	seen := make(map[string]int, len(rules))
	for _, rule := range rules {
		rule.Name = strings.TrimSpace(rule.Name)
		rule.Path = strings.TrimSpace(rule.Path)
		rule.Args = strings.TrimSpace(rule.Args)
		if rule.Name == "" && rule.Path == "" {
			return errors.New("进程规则的名称与路径不能同时为空")
		}
		if rule.Path != "" && (strings.HasSuffix(rule.Path, `\`) || strings.HasSuffix(rule.Path, "/")) {
			cleaned := filepath.Clean(strings.ReplaceAll(rule.Path, "/", `\`))
			if !strings.HasSuffix(cleaned, `\`) {
				cleaned += `\`
			}
			rule.Path = cleaned
		}
		if rule.Name == "" && rule.Path != "" {
			trimmed := strings.TrimRight(rule.Path, `\/`)
			base := filepath.Base(trimmed)
			if strings.HasSuffix(rule.Path, `\`) {
				rule.Name = base
			} else {
				rule.Name = strings.TrimSuffix(base, filepath.Ext(base))
			}
			if rule.Name == "" {
				rule.Name = rule.Path
			}
		}
		key := strings.ToLower(rule.MatchTarget())
		if prevIdx, dup := seen[key]; dup {
			normalized[prevIdx].Enabled = rule.Enabled
			if rule.Name != "" {
				normalized[prevIdx].Name = rule.Name
			}
			if rule.Args != "" {
				normalized[prevIdx].Args = rule.Args
			}
			continue
		}
		seen[key] = len(normalized)
		normalized = append(normalized, rule)
	}
	return writeJSONAtomic(path, normalized, "进程分流列表")
}

func writeJSONAtomic(path string, value any, label string) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化%s失败：%w", label, err)
	}
	temporaryPath := path + ".tmp"
	if err := os.WriteFile(temporaryPath, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("保存%s失败：%w", label, err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("更新%s失败：%w", label, err)
	}
	return nil
}
