package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"sshvpn/internal/config"
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
	configPath := flag.String("config", "config.json", "JSON 配置文件路径")
	verbose := flag.Bool("verbose", false, "显示调试日志")
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

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	manager, err := sshclient.NewManager(cfg, logger)
	if err != nil {
		return err
	}
	defer manager.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
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
	if err := server.ListenAndServe(ctx); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	logger.Info("sshvpn 已停止")
	return nil
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
