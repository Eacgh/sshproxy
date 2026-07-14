package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultSSHPort     = 22
	defaultProxyPort   = 1080
	connectTimeout     = 15 * time.Second
	keepaliveInterval  = 30 * time.Second
	loopbackListenHost = "127.0.0.1"
)

// Config 包含连接信息和可选的自定义 DNS。
// 监听地址、超时、保活和主机密钥存储均由程序内部管理。
type Config struct {
	ServerAddress string `json:"server_address"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	ProxyPort     int    `json:"proxy_port"`
	DNSServer     string `json:"dns_server,omitempty"`
}

// Load 读取 JSON 配置，补全默认端口并执行完整校验。
func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, fmt.Errorf("找不到配置文件 %q", path)
		}
		return Config{}, fmt.Errorf("打开配置文件失败：%w", err)
	}
	defer file.Close()

	var cfg Config
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, describeJSONError(err)
	}
	if err := ensureEOF(decoder); err != nil {
		return Config{}, err
	}
	if err := cfg.applyDefaults(); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return errors.New("配置文件尾部存在无效内容")
	}
	return errors.New("配置文件只能包含一个 JSON 对象")
}

func describeJSONError(err error) error {
	var syntaxError *json.SyntaxError
	if errors.As(err, &syntaxError) {
		return fmt.Errorf("配置文件存在 JSON 语法错误，位置：%d", syntaxError.Offset)
	}
	var typeError *json.UnmarshalTypeError
	if errors.As(err, &typeError) {
		return fmt.Errorf("配置字段 %q 的值类型不正确，位置：%d", typeError.Field, typeError.Offset)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errors.New("配置文件为空或 JSON 内容不完整")
	}
	const unknownFieldPrefix = "json: unknown field "
	if strings.HasPrefix(err.Error(), unknownFieldPrefix) {
		return fmt.Errorf("配置文件包含不再支持的字段 %s，请参照 config.example.json 精简配置", strings.TrimPrefix(err.Error(), unknownFieldPrefix))
	}
	return errors.New("无法解析配置文件中的 JSON 内容")
}

func (c *Config) applyDefaults() error {
	c.ServerAddress = strings.TrimSpace(c.ServerAddress)
	c.Username = strings.TrimSpace(c.Username)
	c.DNSServer = strings.TrimSpace(c.DNSServer)
	if c.ProxyPort == 0 {
		c.ProxyPort = defaultProxyPort
	}

	address, err := normalizeServerAddress(c.ServerAddress)
	if err != nil {
		return err
	}
	c.ServerAddress = address
	if c.DNSServer != "" {
		dnsAddress, err := normalizeDNSAddress(c.DNSServer)
		if err != nil {
			return err
		}
		c.DNSServer = dnsAddress
	}
	return nil
}

// normalizeDNSAddress 只接受 IP，避免解析 DNS 服务器本身时产生启动依赖。
// 未填写端口时自动使用标准 TCP/53。
func normalizeDNSAddress(address string) (string, error) {
	if ip := net.ParseIP(strings.Trim(address, "[]")); ip != nil {
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(strings.Trim(host, "[]")) == nil {
		return "", errors.New("dns_server 必须是 IP 或 IP:端口")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("dns_server 端口必须在 1 到 65535 之间")
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(port)), nil
}

// normalizeServerAddress 在用户没有填写 SSH 端口时自动补充 22。
func normalizeServerAddress(address string) (string, error) {
	if address == "" {
		return "", errors.New("未配置 server_address")
	}
	if host, portText, err := net.SplitHostPort(address); err == nil {
		if host == "" {
			return "", errors.New("server_address 中的主机地址不能为空")
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return "", errors.New("server_address 中的端口必须在 1 到 65535 之间")
		}
		return net.JoinHostPort(host, strconv.Itoa(port)), nil
	}

	// 纯 IPv6 地址没有端口时也自动使用 22。
	trimmedIP := strings.Trim(address, "[]")
	if ip := net.ParseIP(trimmedIP); ip != nil {
		return net.JoinHostPort(ip.String(), strconv.Itoa(defaultSSHPort)), nil
	}
	if strings.Contains(address, ":") {
		return "", errors.New("server_address 格式无效，应填写域名、IP 或 主机:端口")
	}
	return net.JoinHostPort(address, strconv.Itoa(defaultSSHPort)), nil
}

// Validate 校验用户配置，内部设置无需用户参与。
func (c Config) Validate() error {
	if _, _, err := net.SplitHostPort(c.ServerAddress); err != nil {
		return errors.New("server_address 格式无效")
	}
	if c.Username == "" {
		return errors.New("未配置 username")
	}
	if c.Password == "" {
		return errors.New("未配置 password")
	}
	if c.ProxyPort < 1 || c.ProxyPort > 65535 {
		return errors.New("proxy_port 必须在 1 到 65535 之间")
	}
	if c.DNSServer != "" {
		host, _, err := net.SplitHostPort(c.DNSServer)
		if err != nil || net.ParseIP(host) == nil {
			return errors.New("dns_server 格式无效")
		}
	}
	return nil
}

// CustomDNSServer 返回通过 SSH 访问的自定义 DNS；空值表示使用本地 Fake-IP。
func (c Config) CustomDNSServer() string {
	return c.DNSServer
}

// SSHAddress 返回包含端口的 SSH 服务器地址。
func (c Config) SSHAddress() string {
	return c.ServerAddress
}

// SOCKSListen 返回固定在本机回环网卡上的代理监听地址。
func (c Config) SOCKSListen() string {
	return net.JoinHostPort(loopbackListenHost, strconv.Itoa(c.ProxyPort))
}

// ConnectTimeout 返回程序内部统一使用的连接超时时间。
func (Config) ConnectTimeout() time.Duration {
	return connectTimeout
}

// KeepaliveInterval 返回程序内部统一使用的 SSH 保活间隔。
func (Config) KeepaliveInterval() time.Duration {
	return keepaliveInterval
}
