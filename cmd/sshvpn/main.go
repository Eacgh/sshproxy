package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
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
	"time"

	"sshvpn/internal/config"
	"sshvpn/internal/globalproxy"
	"sshvpn/internal/portable"
	"sshvpn/internal/socks5"
	"sshvpn/internal/sshclient"
	"sshvpn/internal/stats"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sshvpn 运行失败：", err)
		os.Exit(1)
	}
}

func run() (returned error) {
	defaultConfigPath, err := portable.File("config.json")
	if err != nil {
		return err
	}
	configPath := flag.String("config", defaultConfigPath, "JSON 配置文件路径")
	profile := flag.String("profile", "", "从服务器列表 servers.json 中按名称加载配置（与 -config 二选一）")
	verbose := flag.Bool("verbose", false, "显示调试日志")
	controlStdin := flag.Bool("control-stdin", false, "允许 GUI 通过标准输入停止程序")
	globalMode := flag.Bool("global", false, "启用 Windows 全局 TCP 代理")
	resetTraffic := flag.Bool("reset-traffic", false, "清零累计流量统计")
	configureUsage()
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	handlerOptions := &slog.HandlerOptions{Level: level, ReplaceAttr: localizeLogAttribute}
	// 日志双写：控制台（GUI 通过它解析日志）与程序目录 logs/ 下的本地文件。
	handlers := []slog.Handler{slog.NewTextHandler(os.Stderr, handlerOptions)}
	if logFile, err := openLogFile(); err != nil {
		slog.New(handlers[0]).Warn("无法创建本地日志文件，本次仅输出到控制台", "错误", err)
	} else {
		handlers = append(handlers, slog.NewTextHandler(logFile, handlerOptions))
	}
	logger := slog.New(slog.NewMultiHandler(handlers...))
	// 之后发生的启动失败也写入本地日志文件，方便离线排查；
	// 控制台仍然由 main 输出统一的“sshvpn 运行失败”提示。
	defer func() {
		if returned != nil {
			logger.Error("sshvpn 运行失败", "错误", returned)
		}
	}()
	if *globalMode {
		if err := globalproxy.Recover(logger); err != nil {
			return err
		}
	}

	var cfg config.Config
	if *profile != "" {
		// GUI 模式：直接从服务器列表加载指定条目，不再需要 config.json。
		serversPath := filepath.Join(filepath.Dir(*configPath), "servers.json")
		cfg, err = config.LoadProfile(serversPath, *profile)
	} else {
		cfg, err = config.Load(*configPath)
	}
	if err != nil {
		return err
	}

	// 流量统计：从程序目录加载累计值，-reset-traffic 时清零；
	// 退出前把最新累计值写回，实现跨重启累计。
	trafficPath, err := portable.File("traffic.json")
	if err != nil {
		return err
	}
	traffic := new(stats.Traffic)
	if *resetTraffic {
		if err := stats.RemoveTraffic(trafficPath); err != nil {
			return err
		}
		logger.Info("已清零累计流量统计")
	} else {
		upload, download, err := stats.LoadTraffic(trafficPath)
		if err != nil {
			return err
		}
		traffic.Restore(upload, download)
	}
	defer func() {
		upload, download := traffic.Snapshot()
		if err := stats.SaveTraffic(trafficPath, upload, download); err != nil {
			logger.Warn("保存流量统计失败", "错误", err)
		}
	}()

	manager, err := sshclient.NewManager(cfg, logger)
	if err != nil {
		return err
	}
	defer manager.Close()

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancelRun := context.WithCancel(signalCtx)
	defer cancelRun()
	go stats.RunReporter(ctx, traffic, logger)
	if *controlStdin {
		go watchControlInput(os.Stdin, cancelRun, logger)
	}
	connectCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout())
	err = manager.Connect(connectCtx)
	cancel()
	if err != nil {
		return err
	}

	server, err := socks5.NewWithStats(cfg.SOCKSListen(), cfg.ConnectTimeout(), manager, logger, traffic)
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
			Traffic:     traffic,
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

// openLogFile 在程序目录创建 logs 子目录，并打开本次启动的日志文件。
// 文件名格式为 logs/日期-随机标识.log，多次启动互不覆盖，便于按会话排查。
func openLogFile() (*os.File, error) {
	directory, err := portable.Directory()
	if err != nil {
		return nil, err
	}
	logsDirectory := filepath.Join(directory, "logs")
	if err := os.MkdirAll(logsDirectory, 0o755); err != nil {
		return nil, err
	}
	identifier, err := randomIdentifier()
	if err != nil {
		return nil, err
	}
	name := time.Now().Format("2006-01-02") + "-" + identifier + ".log"
	return os.OpenFile(filepath.Join(logsDirectory, name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
}

// randomIdentifier 生成短随机十六进制标识作为日志文件名后缀。
func randomIdentifier() (string, error) {
	var buffer [6]byte
	if _, err := rand.Read(buffer[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer[:]), nil
}

// configureUsage 用中文输出命令行帮助，避免标准 flag 帮助混入英文标题。
func configureUsage() {
	flag.Usage = func() {
		output := flag.CommandLine.Output()
		fmt.Fprintf(output, "用法：%s [选项]\n\n", filepath.Base(os.Args[0]))
		fmt.Fprintln(output, "选项：")
		fmt.Fprintln(output, "  -config <路径>")
		fmt.Fprintln(output, "        JSON 配置文件路径（默认：config.json）")
		fmt.Fprintln(output, "  -profile <名称>")
		fmt.Fprintln(output, "        从 servers.json 服务器列表中按名称加载配置")
		fmt.Fprintln(output, "  -verbose")
		fmt.Fprintln(output, "        显示调试日志")
		fmt.Fprintln(output, "  -control-stdin")
		fmt.Fprintln(output, "        允许 GUI 通过标准输入停止程序")
		fmt.Fprintln(output, "  -global")
		fmt.Fprintln(output, "        启用 Windows 全局 TCP 代理（需要管理员权限）")
		fmt.Fprintln(output, "  -reset-traffic")
		fmt.Fprintln(output, "        清零累计流量统计")
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
