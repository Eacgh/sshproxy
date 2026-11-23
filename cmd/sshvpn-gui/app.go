package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"sshvpn/internal/config"
	"sshvpn/internal/core"
	"sshvpn/internal/globalproxy"
	"sshvpn/internal/portable"
	"sshvpn/internal/tray"
)

const maxBufferedLogs = 1000

// BootstrapState 包含前端首屏渲染所需的全部初始数据。
type BootstrapState struct {
	BaseDirectory string                   `json:"base_directory"`
	Servers       []config.ServerProfile   `json:"servers"`
	Processes     []config.ProcessRule     `json:"processes"`
	Status        core.StatusSnapshot      `json:"status"`
	SelectedName  string                   `json:"selected_name"`
	SelectedMode  config.ProxyMode         `json:"selected_mode"`
	Logs          []string                 `json:"logs"`
}

// ProcessRulesUpdateResult 描述保存进程分流规则并热生效后的结果摘要。
type ProcessRulesUpdateResult struct {
	Processes         []config.ProcessRule `json:"processes"`
	AppliedLive       bool                 `json:"applied_live"`
	EnabledCount      int                  `json:"enabled_count"`
	ClosedConnections int                  `json:"closed_connections"`
}

// App 是 Wails 后端控制器，向前端暴露绑定方法并协调引擎与系统托盘。
type App struct {
	baseDir       string
	configPath    string
	serversPath   string
	processesPath string
	engine        *core.Engine
	tray          *tray.Tray

	ctx           context.Context
	exitRequested atomic.Bool
	shutdownOnce  sync.Once

	storeMu     sync.Mutex
	mu          sync.Mutex
	lastProfile string
	lastMode    config.ProxyMode
	logs        []string
}

// NewApp 创建便携版应用实例并初始化核心引擎。
func NewApp() (*App, error) {
	baseDir, err := portable.Directory()
	if err != nil {
		return nil, err
	}
	app := &App{
		baseDir:       baseDir,
		configPath:    filepath.Join(baseDir, "config.json"),
		serversPath:   filepath.Join(baseDir, "servers.json"),
		processesPath: filepath.Join(baseDir, "processes.json"),
		lastMode:      config.ModeProcess,
	}

	engine, err := core.NewEngine(baseDir, core.Callbacks{
		OnLog:     app.handleLog,
		OnState:   app.handleState,
		OnTraffic: app.handleTraffic,
	})
	if err != nil {
		return nil, err
	}
	app.engine = engine
	return app, nil
}

// WebviewUserDataPath 将 WebView2 用户数据固定在程序目录，保持完全便携并在提权下稳定运行。
func (a *App) WebviewUserDataPath() string {
	return filepath.Join(a.baseDir, ".webview2")
}

// OnStartup 在 Wails 窗口就绪后恢复上次异常退出的路由并启动 Win32 托盘。
func (a *App) OnStartup(ctx context.Context) {
	a.ctx = ctx
	if err := a.engine.Recover(); err != nil {
		a.appendSystemLog(fmt.Sprintf("恢复网络状态失败：%v", err))
	}

	a.tray = tray.Start("SSH VPN - 未连接", tray.Callbacks{
		OnShow:   a.ShowWindow,
		OnToggle: a.trayToggle,
		OnExit:   a.QuitApp,
	})
	a.syncTrayStatus(a.engine.Status())
}

// OnBeforeClose 拦截窗口关闭按钮，改为隐藏到系统托盘；仅 QuitApp 触发真正退出。
func (a *App) OnBeforeClose(ctx context.Context) bool {
	if a.exitRequested.Load() {
		return false
	}
	wailsruntime.WindowHide(ctx)
	return true
}

// OnShutdown 在应用退出前安全停止代理（清理 Wintun 路由并保存流量）并移除托盘图标。
func (a *App) OnShutdown(context.Context) {
	a.shutdownOnce.Do(func() {
		_ = a.engine.Stop()
		if a.tray != nil {
			a.tray.Close()
		}
	})
}

// ShowWindow 从托盘或单实例唤醒主窗口。
func (a *App) ShowWindow() {
	if a.ctx == nil {
		return
	}
	wailsruntime.WindowShow(a.ctx)
	wailsruntime.WindowUnminimise(a.ctx)
}

// QuitApp 停止代理、移除托盘并退出程序。
func (a *App) QuitApp() {
	if !a.exitRequested.CompareAndSwap(false, true) {
		return
	}
	if a.ctx != nil {
		wailsruntime.WindowHide(a.ctx)
	}
	_ = a.engine.Stop()
	if a.tray != nil {
		a.tray.Close()
	}
	if a.ctx != nil {
		wailsruntime.Quit(a.ctx)
	}
}

// GetBootstrapState 返回首屏初始化所需的服务器、进程规则、状态与日志缓存。
func (a *App) GetBootstrapState() (BootstrapState, error) {
	servers, migrated, err := config.MigrateFromLegacyConfig(a.configPath, a.serversPath)
	if err != nil {
		return BootstrapState{}, err
	}
	if migrated {
		a.appendSystemLog("已从旧版 config.json 自动生成默认服务器条目")
	}

	processes, err := config.LoadProcesses(a.processesPath)
	if err != nil {
		return BootstrapState{}, err
	}

	a.mu.Lock()
	if a.lastProfile == "" && len(servers) > 0 {
		a.lastProfile = servers[0].Name
	}
	selectedName := a.lastProfile
	selectedMode := a.lastMode
	logsCopy := append([]string(nil), a.logs...)
	a.mu.Unlock()

	if servers == nil {
		servers = []config.ServerProfile{}
	}
	if processes == nil {
		processes = []config.ProcessRule{}
	}
	if logsCopy == nil {
		logsCopy = []string{}
	}

	return BootstrapState{
		BaseDirectory: a.baseDir,
		Servers:       servers,
		Processes:     processes,
		Status:        a.engine.Status(),
		SelectedName:  selectedName,
		SelectedMode:  selectedMode,
		Logs:          logsCopy,
	}, nil
}

// SetSelection 记录界面当前选中的服务器和代理模式，供托盘“连接”菜单使用。
func (a *App) SetSelection(profileName, mode string) {
	parsed, err := config.ParseProxyMode(mode)
	if err != nil {
		return
	}
	a.mu.Lock()
	a.lastProfile = strings.TrimSpace(profileName)
	a.lastMode = parsed
	a.mu.Unlock()
}

// SaveServer 新增或更新服务器条目并写入 servers.json。
func (a *App) SaveServer(originalName string, profile config.ServerProfile) ([]config.ServerProfile, error) {
	a.storeMu.Lock()
	defer a.storeMu.Unlock()

	servers, err := config.LoadServers(a.serversPath)
	if err != nil {
		return nil, err
	}
	profile.Name = strings.TrimSpace(profile.Name)
	originalName = strings.TrimSpace(originalName)

	replaced := false
	if originalName != "" {
		for i := range servers {
			if servers[i].Name == originalName {
				servers[i] = profile
				replaced = true
				break
			}
		}
	}
	if !replaced {
		servers = append(servers, profile)
	}
	if err := config.SaveServers(a.serversPath, servers); err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.lastProfile = profile.Name
	a.mu.Unlock()
	a.appendSystemLog(fmt.Sprintf("已保存服务器配置：%s", profile.Name))
	return config.LoadServers(a.serversPath)
}

// DeleteServer 从 servers.json 删除指定名称的服务器。
func (a *App) DeleteServer(name string) ([]config.ServerProfile, error) {
	a.storeMu.Lock()
	defer a.storeMu.Unlock()

	servers, err := config.LoadServers(a.serversPath)
	if err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	filtered := make([]config.ServerProfile, 0, len(servers))
	removed := false
	for _, entry := range servers {
		if entry.Name == name && !removed {
			removed = true
			continue
		}
		filtered = append(filtered, entry)
	}
	if err := config.SaveServers(a.serversPath, filtered); err != nil {
		return nil, err
	}
	a.mu.Lock()
	if a.lastProfile == name {
		a.lastProfile = ""
		if len(filtered) > 0 {
			a.lastProfile = filtered[0].Name
		}
	}
	a.mu.Unlock()
	a.appendSystemLog(fmt.Sprintf("已删除服务器：%s", name))
	if filtered == nil {
		filtered = []config.ServerProfile{}
	}
	return filtered, nil
}

// SaveProcessRules 保存进程分流规则，并在运行中热更新分流器、立即断开路由发生变化的活动连接。
func (a *App) SaveProcessRules(rules []config.ProcessRule) (ProcessRulesUpdateResult, error) {
	a.storeMu.Lock()
	defer a.storeMu.Unlock()

	if err := config.SaveProcesses(a.processesPath, rules); err != nil {
		return ProcessRulesUpdateResult{}, err
	}
	saved, err := config.LoadProcesses(a.processesPath)
	if err != nil {
		return ProcessRulesUpdateResult{}, err
	}
	if saved == nil {
		saved = []config.ProcessRule{}
	}
	applied, closed := a.engine.UpdateProcessRules(saved)
	enabledCount := 0
	for _, rule := range saved {
		if rule.IsEnabled() && rule.MatchTarget() != "" {
			enabledCount++
		}
	}
	return ProcessRulesUpdateResult{
		Processes:         saved,
		AppliedLive:       applied,
		EnabledCount:      enabledCount,
		ClosedConnections: closed,
	}, nil
}

// ListRunningProcesses 返回系统当前运行的用户态进程列表，供前端勾选添加。
func (a *App) ListRunningProcesses() ([]globalproxy.RunningProcess, error) {
	list, err := globalproxy.ListRunningProcesses()
	if err != nil {
		return nil, err
	}
	if list == nil {
		list = []globalproxy.RunningProcess{}
	}
	return list, nil
}

// PickExecutable 打开系统文件选择框以选取要分流的可执行程序。
func (a *App) PickExecutable() (string, error) {
	if a.ctx == nil {
		return "", errors.New("窗口尚未初始化")
	}
	return wailsruntime.OpenFileDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title: "选择要代理的程序",
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "可执行程序 (*.exe)", Pattern: "*.exe"},
		},
	})
}

// PickDirectory 打开系统文件夹选择框以将整个目录下的程序加入分流白名单。
func (a *App) PickDirectory() (string, error) {
	if a.ctx == nil {
		return "", errors.New("窗口尚未初始化")
	}
	dir, err := wailsruntime.OpenDirectoryDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title: "选择软件安装目录（目录下全部程序走代理）",
	})
	if err != nil || strings.TrimSpace(dir) == "" {
		return dir, err
	}
	cleaned := filepath.Clean(dir)
	if !strings.HasSuffix(cleaned, `\`) {
		cleaned += `\`
	}
	return cleaned, nil
}

// Connect 启动指定服务器与代理模式。
func (a *App) Connect(profileName, modeText string) error {
	profileName = strings.TrimSpace(profileName)
	if profileName == "" {
		return errors.New("请先添加并选择一条服务器配置")
	}
	mode, err := config.ParseProxyMode(modeText)
	if err != nil {
		return err
	}
	var rules []config.ProcessRule
	if mode == config.ModeProcess {
		rules, err = config.LoadProcesses(a.processesPath)
		if err != nil {
			return err
		}
		enabledCount := 0
		for _, rule := range rules {
			if rule.IsEnabled() && rule.MatchTarget() != "" {
				enabledCount++
			}
		}
		if enabledCount == 0 {
			a.appendSystemLog("提示：当前进程分流白名单为空，所有程序将暂时经物理网卡直连")
		}
	}

	a.mu.Lock()
	a.lastProfile = profileName
	a.lastMode = mode
	a.mu.Unlock()

	return a.engine.Start(context.Background(), core.StartRequest{
		ServersPath:  a.serversPath,
		ProfileName:  profileName,
		Mode:         mode,
		ProcessRules: rules,
		Verbose:      true,
	})
}

// Disconnect 断开当前代理连接。
func (a *App) Disconnect() error {
	return a.engine.Stop()
}

// ResetTraffic 清零累计流量统计（支持连接中免重启清零）。
func (a *App) ResetTraffic() error {
	if err := a.engine.ResetTraffic(); err != nil {
		return err
	}
	a.appendSystemLog("已重置累计流量统计")
	return nil
}

// ClearLogs 清空后端内存日志缓存。
func (a *App) ClearLogs() {
	a.mu.Lock()
	a.logs = nil
	a.mu.Unlock()
}

// OpenDataDirectory 在 Windows 资源管理器中打开程序目录。
func (a *App) OpenDataDirectory() error {
	return exec.Command("explorer.exe", a.baseDir).Start()
}

func (a *App) trayToggle() {
	snap := a.engine.Status()
	if snap.State == core.StateStarting || snap.State == core.StateConnected {
		_ = a.Disconnect()
		return
	}
	if snap.State == core.StateStopping {
		return
	}

	a.mu.Lock()
	profile := a.lastProfile
	mode := a.lastMode
	a.mu.Unlock()

	if profile == "" {
		a.ShowWindow()
		return
	}
	if err := a.Connect(profile, string(mode)); err != nil {
		a.ShowWindow()
	}
}

func (a *App) appendSystemLog(msg string) {
	a.handleLog("系统  [信息] " + msg)
}

func (a *App) handleLog(line string) {
	a.mu.Lock()
	a.logs = append(a.logs, line)
	if len(a.logs) > maxBufferedLogs {
		a.logs = append([]string(nil), a.logs[len(a.logs)-maxBufferedLogs:]...)
	}
	a.mu.Unlock()

	if a.ctx != nil {
		wailsruntime.EventsEmit(a.ctx, "log", line)
	}
}

func (a *App) handleState(status core.StatusSnapshot) {
	a.syncTrayStatus(status)
	if a.ctx != nil {
		wailsruntime.EventsEmit(a.ctx, "state", status)
	}
}

func (a *App) handleTraffic(upload, download uint64) {
	if a.ctx != nil {
		wailsruntime.EventsEmit(a.ctx, "traffic", map[string]uint64{
			"upload":   upload,
			"download": download,
		})
	}
}

func (a *App) syncTrayStatus(status core.StatusSnapshot) {
	if a.tray == nil {
		return
	}
	label := "未连接"
	switch status.State {
	case core.StateStarting:
		label = "正在连接"
	case core.StateConnected:
		switch status.Mode {
		case config.ModeProcess:
			label = "已连接（按进程分流）"
		case config.ModeSOCKS5:
			label = "已连接（SOCKS5）"
		default:
			label = "已连接（全局 TCP）"
		}
	case core.StateStopping:
		label = "正在断开"
	case core.StateFaulted:
		label = "连接失败"
	}
	canDisconnect := status.State == core.StateStarting || status.State == core.StateConnected
	a.tray.SetStatus("SSH VPN - "+label, canDisconnect)
}
