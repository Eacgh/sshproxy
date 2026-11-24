package main

import (
	"context"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"

	"sshvpn/internal/config"
	"sshvpn/internal/core"
	"sshvpn/internal/portable"
)

func main() {
	if debug.SetMemoryLimit(-1) == math.MaxInt64 {
		debug.SetMemoryLimit(256 << 20)
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sshvpn 运行失败：", err)
		os.Exit(1)
	}
}

func run() error {
	baseDir, err := portable.Directory()
	if err != nil {
		return err
	}
	defaultConfigPath := filepath.Join(baseDir, "config.json")
	configPath := flag.String("config", defaultConfigPath, "JSON 配置文件路径")
	profile := flag.String("profile", "", "从服务器列表 servers.json 中按名称加载配置（与 -config 二选一）")
	verbose := flag.Bool("verbose", false, "显示调试日志")
	globalMode := flag.Bool("global", false, "启用 Windows 全局 TCP 代理（等价于 -mode=global）")
	modeFlag := flag.String("mode", "", "代理模式：socks5（仅本地 SOCKS5）、global（全局 TCP）或 process（按进程分流）")
	resetTraffic := flag.Bool("reset-traffic", false, "清零累计流量统计")
	configureUsage()
	flag.Parse()

	mode := config.ModeSOCKS5
	if *modeFlag != "" {
		parsed, err := config.ParseProxyMode(*modeFlag)
		if err != nil {
			return err
		}
		mode = parsed
	} else if *globalMode {
		mode = config.ModeGlobal
	}

	var processRules []config.ProcessRule
	if mode == config.ModeProcess {
		processesPath := filepath.Join(filepath.Dir(*configPath), "processes.json")
		processRules, err = config.LoadProcesses(processesPath)
		if err != nil {
			return err
		}
	}

	engine, err := core.NewEngine(baseDir, core.Callbacks{
		ExtraLogOut: os.Stderr,
		LogTraffic:  true,
	})
	if err != nil {
		return err
	}

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	serversPath := filepath.Join(filepath.Dir(*configPath), "servers.json")
	if err := engine.Start(signalCtx, core.StartRequest{
		ConfigPath:   *configPath,
		ServersPath:  serversPath,
		ProfileName:  *profile,
		Mode:         mode,
		ProcessRules: processRules,
		Verbose:      *verbose,
		ResetTraffic: *resetTraffic,
	}); err != nil {
		return err
	}

	waitErr := engine.Wait()
	if stopErr := engine.Stop(); stopErr != nil && waitErr == nil {
		waitErr = stopErr
	}
	return waitErr
}

func configureUsage() {
	flag.Usage = func() {
		output := flag.CommandLine.Output()
		fmt.Fprintf(output, "用法：%s [选项]\n\n", filepath.Base(os.Args[0]))
		fmt.Fprintln(output, "选项：")
		fmt.Fprintln(output, "  -config <路径>")
		fmt.Fprintln(output, "        JSON 配置文件路径（默认：config.json）")
		fmt.Fprintln(output, "  -profile <名称>")
		fmt.Fprintln(output, "        从 servers.json 服务器列表中按名称加载配置")
		fmt.Fprintln(output, "  -mode <模式>")
		fmt.Fprintln(output, "        代理模式：socks5（默认，仅本地 SOCKS5）、global（全局 TCP）、process（按进程分流）")
		fmt.Fprintln(output, "  -global")
		fmt.Fprintln(output, "        启用 Windows 全局 TCP 代理（需要管理员权限，等价于 -mode=global）")
		fmt.Fprintln(output, "  -verbose")
		fmt.Fprintln(output, "        显示调试日志")
		fmt.Fprintln(output, "  -reset-traffic")
		fmt.Fprintln(output, "        清零累计流量统计")
	}
}
