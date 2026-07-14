package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"sshvpn/internal/config"
	"sshvpn/internal/globalproxy"
	"sshvpn/internal/portable"
	"sshvpn/internal/socks5"
	"sshvpn/internal/sshclient"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sshvpn 运行失败：", err)
		os.Exit(1)
	}
}

func run() error {
	defaultConfigPath, err := portable.File("config.json")
	if err != nil {
		return err
	}
	configPath := flag.String("config", defaultConfigPath, "JSON 配置文件路径")
	verbose := flag.Bool("verbose", false, "显示调试日志")
	controlStdin := flag.Bool("control-stdin", false, "允许 GUI 通过标准输入停止程序")
	globalMode := flag.Bool("global", false, "启用 Windows 全局 TCP 代理")
	configureUsage()
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: localizeLogAttribute,
	}))
	if *globalMode {
		if err := globalproxy.Recover(logger); err != nil {
			return err
		}
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	manager, err := sshclient.NewManager(cfg, logger)
	if err != nil {
		return err
	}
	defer manager.Close()

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancelRun := context.WithCancel(signalCtx)
	defer cancelRun()
	if *controlStdin {
		go watchControlInput(os.Stdin, cancelRun, logger)
	}
	connectCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout())
	err = manager.Connect(connectCtx)
	cancel()
	if err != nil {
		return err
	}

	server, err := socks5.New(cfg.SOCKSListen(), cfg.ConnectTimeout(), manager, logger)
	if err != nil {
		return err
	}
	defer server.Close()
	listener, err := net.Listen("tcp", cfg.SOCKSListen())
	if err != nil {
		return fmt.Errorf("监听 SOCKS5 连接失败：%w", err)
	}

	var globalController globalproxy.Controller
	if *globalMode {
		serverIP, err := manager.ServerIP()
		if err != nil {
			listener.Close()
			return err
		}
		globalController = globalproxy.New(globalproxy.Options{
			SSHServerIP: serverIP,
			Dialer:      manager,
			DNSServer:   cfg.CustomDNSServer(),
			Logger:      logger,
		})
		if err := globalController.Start(ctx); err != nil {
			listener.Close()
			return err
		}
	}

	serveErr := server.Serve(ctx, listener)
	var cleanupErr error
	if globalController != nil {
		cleanupErr = globalController.Close()
	}
	if serveErr != nil && !errors.Is(serveErr, net.ErrClosed) {
		return serveErr
	}
	if cleanupErr != nil {
		return cleanupErr
	}
	logger.Info("sshvpn 已停止")
	return nil
}

// watchControlInput 接收 GUI 发来的 stop 命令，并触发与 Ctrl+C 相同的清理流程。
func watchControlInput(reader io.Reader, cancel context.CancelFunc, logger *slog.Logger) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		command := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if command == "stop" || command == "exit" || command == "quit" {
			logger.Info("收到 GUI 退出命令")
			cancel()
			return
		}
	}
	if err := scanner.Err(); err != nil {
		logger.Warn("读取 GUI 控制命令失败", "错误", err)
	}
}

// configureUsage 用中文输出命令行帮助，避免标准 flag 帮助混入英文标题。
func configureUsage() {
	flag.Usage = func() {
		output := flag.CommandLine.Output()
		fmt.Fprintf(output, "用法：%s [选项]\n\n", filepath.Base(os.Args[0]))
		fmt.Fprintln(output, "选项：")
		fmt.Fprintln(output, "  -config <路径>")
		fmt.Fprintln(output, "        JSON 配置文件路径（默认：config.json）")
		fmt.Fprintln(output, "  -verbose")
		fmt.Fprintln(output, "        显示调试日志")
		fmt.Fprintln(output, "  -control-stdin")
		fmt.Fprintln(output, "        允许 GUI 通过标准输入停止程序")
		fmt.Fprintln(output, "  -global")
		fmt.Fprintln(output, "        启用 Windows 全局 TCP 代理（需要管理员权限）")
	}
}

// localizeLogAttribute 将 slog 的内置字段名和日志级别转换为中文。
func localizeLogAttribute(_ []string, attribute slog.Attr) slog.Attr {
	switch attribute.Key {
	case slog.TimeKey:
		attribute.Key = "时间"
	case slog.LevelKey:
		attribute.Key = "级别"
		level := attribute.Value.Any().(slog.Level)
		switch {
		case level <= slog.LevelDebug:
			attribute.Value = slog.StringValue("调试")
		case level <= slog.LevelInfo:
			attribute.Value = slog.StringValue("信息")
		case level <= slog.LevelWarn:
			attribute.Value = slog.StringValue("警告")
		default:
			attribute.Value = slog.StringValue("错误")
		}
	case slog.MessageKey:
		attribute.Key = "消息"
	}
	return attribute
}
