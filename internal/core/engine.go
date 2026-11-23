// Package core 统一封装 SSH VPN 的代理生命周期、日志落盘、流量统计与状态回调，
// 同时服务于桌面 GUI（Wails v2）和命令行入口（cmd/sshvpn）。
package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"sshvpn/internal/config"
	"sshvpn/internal/globalproxy"
	"sshvpn/internal/portable"
	"sshvpn/internal/socks5"
	"sshvpn/internal/sshclient"
	"sshvpn/internal/stats"
)

// State 表示核心引擎的当前运行状态。
type State string

const (
	StateStopped   State = "stopped"
	StateStarting  State = "starting"
	StateConnected State = "connected"
	StateStopping  State = "stopping"
	StateFaulted   State = "faulted"
)

// StatusSnapshot 描述引擎向外广播的完整状态快照。
type StatusSnapshot struct {
	State    State            `json:"state"`
	Mode     config.ProxyMode `json:"mode"`
	Profile  string           `json:"profile"`
	Endpoint string           `json:"endpoint"`
	Error    string           `json:"error,omitempty"`
	Upload   uint64           `json:"upload"`
	Download uint64           `json:"download"`
}

// Callbacks 定义核心引擎向外部（GUI/CLI）推送事件的回调。
type Callbacks struct {
	OnLog       func(line string)
	OnState     func(status StatusSnapshot)
	OnTraffic   func(upload, download uint64)
	ExtraLogOut io.Writer
	LogTraffic  bool
}

// StartRequest 描述一次代理会话的启动参数。
type StartRequest struct {
	ConfigPath   string
	ServersPath  string
	ProfileName  string
	Mode         config.ProxyMode
	ProcessRules []config.ProcessRule
	Verbose      bool
	ResetTraffic bool
}

type activeSession struct {
	ctx              context.Context
	cancel           context.CancelFunc
	manager          *sshclient.Manager
	socksServer      *socks5.Server
	listener         net.Listener
	globalController globalproxy.Controller
	logFile          *os.File
	logger           *slog.Logger
	done             chan struct{}

	mu       sync.Mutex
	stopping bool
	err      error
}

// Engine 管理 SSH 连接、SOCKS5、Wintun 全局/按进程分流与流量持久化的完整生命周期。
type Engine struct {
	baseDir     string
	trafficPath string
	traffic     *stats.Traffic
	callbacks   Callbacks

	opMu               sync.Mutex
	stateMu            sync.RWMutex
	status             StatusSnapshot
	session            *activeSession
	lastErr            error
	latestProcessRules []config.ProcessRule
	processRulesSeq    uint64
}

// NewEngine 创建核心引擎并立即加载历史流量累计值；构造阶段不连接网络。
func NewEngine(baseDir string, callbacks Callbacks) (*Engine, error) {
	if strings.TrimSpace(baseDir) == "" {
		dir, err := portable.Directory()
		if err != nil {
			return nil, err
		}
		baseDir = dir
	}
	trafficPath := filepath.Join(baseDir, "traffic.json")
	traffic := new(stats.Traffic)
	upload, download, err := stats.LoadTraffic(trafficPath)
	if err != nil {
		return nil, err
	}
	traffic.Restore(upload, download)

	return &Engine{
		baseDir:     baseDir,
		trafficPath: trafficPath,
		traffic:     traffic,
		callbacks:   callbacks,
		status: StatusSnapshot{
			State:    StateStopped,
			Mode:     config.ModeGlobal,
			Endpoint: "SOCKS5 127.0.0.1:1080",
			Upload:   upload,
			Download: download,
		},
	}, nil
}

// Recover 清理上次异常退出可能遗留的临时网络路由。
func (e *Engine) Recover() error {
	logger := e.newBootstrapLogger(false)
	return globalproxy.Recover(logger)
}

// Status 返回当前引擎状态与流量快照。
func (e *Engine) Status() StatusSnapshot {
	upload, download := e.traffic.Snapshot()
	e.stateMu.RLock()
	snapshot := e.status
	e.stateMu.RUnlock()
	snapshot.Upload = upload
	snapshot.Download = download
	return snapshot
}

// Start 启动代理会话。启动成功时立即返回，内部持续运行直至 Stop 或致命错误。
func (e *Engine) Start(parentCtx context.Context, req StartRequest) error {
	e.opMu.Lock()
	defer e.opMu.Unlock()

	if e.currentSession() != nil {
		return errors.New("代理服务已经在运行")
	}

	mode := req.Mode
	if mode == "" {
		mode = config.ModeGlobal
	}
	if _, err := config.ParseProxyMode(string(mode)); err != nil {
		return err
	}

	logger, logFile := e.openSessionLogger(req.Verbose)
	closeLog := true
	defer func() {
		if closeLog && logFile != nil {
			_ = logFile.Close()
		}
	}()

	failStart := func(err error) error {
		logger.Error("sshvpn 运行失败", "错误", err)
		e.setState(StateFaulted, mode, req.ProfileName, e.Status().Endpoint, err.Error())
		e.setLastErr(err)
		return err
	}

	// 启动前优先恢复上次异常退出可能遗留的 /1 路由，防止残留路由导致断网。
	if err := globalproxy.Recover(logger); err != nil {
		return failStart(err)
	}

	var cfg config.Config
	var err error
	if strings.TrimSpace(req.ProfileName) != "" {
		serversPath := req.ServersPath
		if serversPath == "" {
			serversPath = filepath.Join(e.baseDir, "servers.json")
		}
		cfg, err = config.LoadProfile(serversPath, req.ProfileName)
	} else {
		configPath := req.ConfigPath
		if configPath == "" {
			configPath = filepath.Join(e.baseDir, "config.json")
		}
		cfg, err = config.Load(configPath)
	}
	if err != nil {
		return failStart(err)
	}

	endpoint := formatEndpointText(mode, cfg.SOCKSListen())
	e.setLastErr(nil)
	e.setState(StateStarting, mode, req.ProfileName, endpoint, "")

	e.stateMu.RLock()
	startSeq := e.processRulesSeq
	e.stateMu.RUnlock()

	if req.ResetTraffic {
		if err := stats.RemoveTraffic(e.trafficPath); err != nil {
			return failStart(err)
		}
		e.traffic.Reset()
		e.emitTraffic(0, 0)
		logger.Info("已清零累计流量统计")
	}

	manager, err := sshclient.NewManager(cfg, logger)
	if err != nil {
		return failStart(err)
	}

	runCtx, cancelRun := context.WithCancel(parentCtx)
	connectCtx, cancelConnect := context.WithTimeout(runCtx, cfg.ConnectTimeout())
	err = manager.Connect(connectCtx)
	cancelConnect()
	if err != nil {
		cancelRun()
		_ = manager.Close()
		return failStart(err)
	}

	server, err := socks5.NewWithStats(cfg.SOCKSListen(), cfg.ConnectTimeout(), manager, logger, e.traffic)
	if err != nil {
		cancelRun()
		_ = manager.Close()
		return failStart(err)
	}
	listener, err := net.Listen("tcp", cfg.SOCKSListen())
	if err != nil {
		cancelRun()
		_ = server.Close()
		_ = manager.Close()
		return failStart(fmt.Errorf("监听 SOCKS5 连接失败：%w", err))
	}

	var globalController globalproxy.Controller
	controllerSeq := startSeq
	if mode == config.ModeGlobal || mode == config.ModeProcess {
		serverIP, err := manager.ServerIP()
		if err != nil {
			cancelRun()
			_ = listener.Close()
			_ = server.Close()
			_ = manager.Close()
			return failStart(err)
		}
		initialRules := req.ProcessRules
		if mode == config.ModeProcess {
			e.stateMu.RLock()
			if e.processRulesSeq > startSeq {
				initialRules = append([]config.ProcessRule(nil), e.latestProcessRules...)
				controllerSeq = e.processRulesSeq
			}
			e.stateMu.RUnlock()
		}
		globalController = globalproxy.New(globalproxy.Options{
			SSHServerIP:  serverIP,
			Dialer:       manager,
			DNSServer:    cfg.CustomDNSServer(),
			Logger:       logger,
			Mode:         mode,
			ProcessRules: initialRules,
			Traffic:      e.traffic,
		})
		if err := globalController.Start(runCtx); err != nil {
			cancelRun()
			_ = globalController.Close()
			_ = listener.Close()
			_ = server.Close()
			_ = manager.Close()
			return failStart(err)
		}
	}

	sess := &activeSession{
		ctx:              runCtx,
		cancel:           cancelRun,
		manager:          manager,
		socksServer:      server,
		listener:         listener,
		globalController: globalController,
		logFile:          logFile,
		logger:           logger,
		done:             make(chan struct{}),
	}
	var pendingRules []config.ProcessRule
	hasPendingRules := false
	e.stateMu.Lock()
	e.session = sess
	if mode == config.ModeProcess && e.processRulesSeq > controllerSeq {
		hasPendingRules = true
		pendingRules = append([]config.ProcessRule(nil), e.latestProcessRules...)
	}
	e.stateMu.Unlock()

	if hasPendingRules && globalController != nil {
		globalController.UpdateProcessRules(pendingRules)
	}

	closeLog = false
	e.setState(StateConnected, mode, req.ProfileName, endpoint, "")

	go stats.RunPersistLoop(runCtx, e.trafficPath, e.traffic, logger)
	if e.callbacks.LogTraffic {
		go stats.RunReporter(runCtx, e.traffic, logger)
	}
	go e.runTrafficEmitter(runCtx)
	go e.serveSession(sess, mode, req.ProfileName, endpoint)

	return nil
}

func (e *Engine) serveSession(sess *activeSession, mode config.ProxyMode, profile, endpoint string) {
	defer close(sess.done)
	defer func() {
		if sess.logFile != nil {
			_ = sess.logFile.Close()
		}
	}()

	serveErr := sess.socksServer.Serve(sess.ctx, sess.listener)
	sess.cancel()

	var cleanupErr error
	if sess.globalController != nil {
		cleanupErr = sess.globalController.Close()
	}
	_ = sess.socksServer.Close()
	_ = sess.manager.Close()

	upload, download := e.traffic.Snapshot()
	if saveErr := stats.SaveTraffic(e.trafficPath, upload, download); saveErr != nil {
		sess.logger.Warn("保存流量统计失败", "错误", saveErr)
	}
	e.emitTraffic(upload, download)

	sess.mu.Lock()
	stopping := sess.stopping
	sess.mu.Unlock()

	var finalErr error
	if serveErr != nil && !errors.Is(serveErr, net.ErrClosed) {
		finalErr = serveErr
	} else if cleanupErr != nil {
		finalErr = cleanupErr
	}

	e.stateMu.Lock()
	if e.session == sess {
		e.session = nil
	}
	e.stateMu.Unlock()

	if finalErr != nil && !stopping {
		sess.logger.Error("sshvpn 运行失败", "错误", finalErr)
		sess.mu.Lock()
		sess.err = finalErr
		sess.mu.Unlock()
		e.setLastErr(finalErr)
		e.setState(StateFaulted, mode, profile, endpoint, finalErr.Error())
		return
	}

	sess.logger.Info("sshvpn 已停止")
	if finalErr != nil {
		sess.mu.Lock()
		sess.err = finalErr
		sess.mu.Unlock()
		e.setLastErr(finalErr)
	}
	e.setState(StateStopped, mode, profile, endpoint, "")
}

// Stop 优雅停止当前运行中的代理会话，并等待网络与 SSH 资源全部清理完成。
func (e *Engine) Stop() error {
	e.opMu.Lock()
	defer e.opMu.Unlock()

	sess := e.currentSession()
	if sess == nil {
		snap := e.Status()
		e.setState(StateStopped, snap.Mode, snap.Profile, snap.Endpoint, "")
		return nil
	}

	sess.mu.Lock()
	sess.stopping = true
	sess.mu.Unlock()

	snap := e.Status()
	e.setState(StateStopping, snap.Mode, snap.Profile, snap.Endpoint, "")
	sess.cancel()
	<-sess.done

	sess.mu.Lock()
	err := sess.err
	sess.mu.Unlock()
	return err
}

// Wait 阻塞直到当前代理会话退出，并返回停止过程中的错误（如有）。
func (e *Engine) Wait() error {
	sess := e.currentSession()
	if sess == nil {
		return nil
	}
	<-sess.done
	sess.mu.Lock()
	err := sess.err
	sess.mu.Unlock()
	return err
}

// UpdateProcessRules 在按进程分流模式下动态热更新白名单进程列表，并返回是否已在运行态即时生效及断开的连接数。
func (e *Engine) UpdateProcessRules(rules []config.ProcessRule) (bool, int) {
	e.stateMu.Lock()
	e.latestProcessRules = append([]config.ProcessRule(nil), rules...)
	e.processRulesSeq++
	sess := e.session
	mode := e.status.Mode
	e.stateMu.Unlock()

	if sess == nil || sess.globalController == nil || mode != config.ModeProcess {
		return false, 0
	}
	return true, sess.globalController.UpdateProcessRules(rules)
}

// ResetTraffic 清零内存与持久化文件中的流量计数（支持连接运行中免重启重置）。
func (e *Engine) ResetTraffic() error {
	if err := stats.RemoveTraffic(e.trafficPath); err != nil {
		return err
	}
	e.traffic.Reset()
	e.emitTraffic(0, 0)
	snap := e.Status()
	e.setState(snap.State, snap.Mode, snap.Profile, snap.Endpoint, snap.Error)
	return nil
}

// Close 停止一切运行中的服务并释放资源。
func (e *Engine) Close() error {
	return e.Stop()
}

func (e *Engine) currentSession() *activeSession {
	e.stateMu.RLock()
	sess := e.session
	e.stateMu.RUnlock()
	return sess
}

func (e *Engine) setLastErr(err error) {
	e.stateMu.Lock()
	e.lastErr = err
	e.stateMu.Unlock()
}

func (e *Engine) setState(state State, mode config.ProxyMode, profile, endpoint, errText string) {
	upload, download := e.traffic.Snapshot()
	snapshot := StatusSnapshot{
		State:    state,
		Mode:     mode,
		Profile:  profile,
		Endpoint: endpoint,
		Error:    errText,
		Upload:   upload,
		Download: download,
	}
	e.stateMu.Lock()
	e.status = snapshot
	e.stateMu.Unlock()
	if e.callbacks.OnState != nil {
		e.callbacks.OnState(snapshot)
	}
}

func (e *Engine) emitTraffic(upload, download uint64) {
	if e.callbacks.OnTraffic != nil {
		e.callbacks.OnTraffic(upload, download)
	}
}

func (e *Engine) runTrafficEmitter(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	upload, download := e.traffic.Snapshot()
	e.emitTraffic(upload, download)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			upload, download := e.traffic.Snapshot()
			e.emitTraffic(upload, download)
		}
	}
}

func formatEndpointText(mode config.ProxyMode, socksListen string) string {
	switch mode {
	case config.ModeProcess:
		return "按进程分流 · SOCKS5 " + socksListen
	case config.ModeSOCKS5:
		return "SOCKS5 " + socksListen
	default:
		return "全局 TCP · SOCKS5 " + socksListen
	}
}

func (e *Engine) newBootstrapLogger(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	options := &slog.HandlerOptions{Level: level, ReplaceAttr: localizeLogAttribute}
	var handlers []slog.Handler
	if e.callbacks.ExtraLogOut != nil {
		handlers = append(handlers, slog.NewTextHandler(e.callbacks.ExtraLogOut, options))
	}
	if e.callbacks.OnLog != nil {
		handlers = append(handlers, newCallbackLogHandler(level, e.callbacks.OnLog))
	}
	if len(handlers) == 0 {
		return slog.New(slog.NewTextHandler(io.Discard, options))
	}
	return slog.New(slog.NewMultiHandler(handlers...))
}

func (e *Engine) openSessionLogger(verbose bool) (*slog.Logger, *os.File) {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	options := &slog.HandlerOptions{Level: level, ReplaceAttr: localizeLogAttribute}
	var handlers []slog.Handler
	if e.callbacks.ExtraLogOut != nil {
		handlers = append(handlers, slog.NewTextHandler(e.callbacks.ExtraLogOut, options))
	}
	if e.callbacks.OnLog != nil {
		handlers = append(handlers, newCallbackLogHandler(level, e.callbacks.OnLog))
	}
	logFile, err := openLogFile(e.baseDir)
	if err != nil {
		if len(handlers) > 0 {
			slog.New(slog.NewMultiHandler(handlers...)).Warn("无法创建本地日志文件，本次仅输出到界面/控制台", "错误", err)
		}
	} else {
		handlers = append(handlers, slog.NewTextHandler(logFile, options))
	}
	if len(handlers) == 0 {
		return slog.New(slog.NewTextHandler(io.Discard, options)), logFile
	}
	return slog.New(slog.NewMultiHandler(handlers...)), logFile
}

type callbackLogHandler struct {
	level slog.Level
	onLog func(string)
	attrs []slog.Attr
}

func newCallbackLogHandler(level slog.Level, onLog func(string)) *callbackLogHandler {
	return &callbackLogHandler{level: level, onLog: onLog}
}

func (h *callbackLogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *callbackLogHandler) Handle(_ context.Context, record slog.Record) error {
	if h.onLog == nil {
		return nil
	}
	var builder strings.Builder
	builder.WriteString(record.Time.Format("15:04:05"))
	builder.WriteString("  [")
	builder.WriteString(localizeLevelText(record.Level))
	builder.WriteString("] ")
	builder.WriteString(record.Message)

	appendAttr := func(attr slog.Attr) bool {
		if attr.Equal(slog.Attr{}) {
			return true
		}
		builder.WriteByte(' ')
		builder.WriteString(attr.Key)
		builder.WriteByte('=')
		builder.WriteString(attr.Value.String())
		return true
	}
	for _, attr := range h.attrs {
		appendAttr(attr)
	}
	record.Attrs(appendAttr)
	h.onLog(builder.String())
	return nil
}

func (h *callbackLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &callbackLogHandler{level: h.level, onLog: h.onLog, attrs: merged}
}

func (h *callbackLogHandler) WithGroup(string) slog.Handler {
	return h
}

func openLogFile(baseDir string) (*os.File, error) {
	logsDirectory := filepath.Join(baseDir, "logs")
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

func randomIdentifier() (string, error) {
	var buffer [6]byte
	if _, err := rand.Read(buffer[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer[:]), nil
}

func localizeLevelText(level slog.Level) string {
	switch {
	case level <= slog.LevelDebug:
		return "调试"
	case level <= slog.LevelInfo:
		return "信息"
	case level <= slog.LevelWarn:
		return "警告"
	default:
		return "错误"
	}
}

func localizeLogAttribute(_ []string, attribute slog.Attr) slog.Attr {
	switch attribute.Key {
	case slog.TimeKey:
		attribute.Key = "时间"
	case slog.LevelKey:
		attribute.Key = "级别"
		if level, ok := attribute.Value.Any().(slog.Level); ok {
			attribute.Value = slog.StringValue(localizeLevelText(level))
		}
	case slog.MessageKey:
		attribute.Key = "消息"
	}
	return attribute
}
