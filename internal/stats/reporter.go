package stats

import (
	"context"
	"log/slog"
	"time"
)

// 日志输出间隔：秒级刷新足够界面显示，又不至于刷屏。
const trafficLogInterval = time.Second

// RunReporter 每秒把当前累计流量输出为一条日志，供 GUI 解析显示。
// 阻塞直到 ctx 取消；统计值由外部累加，这里只读取。
func RunReporter(ctx context.Context, traffic *Traffic, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	// 启动时先输出一次当前累计值，方便界面立即拿到持久化的旧值。
	report(traffic, logger)
	ticker := time.NewTicker(trafficLogInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			report(traffic, logger)
		}
	}
}

func report(traffic *Traffic, logger *slog.Logger) {
	upload, download := traffic.Snapshot()
	// 输出原始字节数（纯数字），GUI 端负责格式化显示；
	// 输出格式保持稳定，GUI 通过识别“流量统计”前缀解析数值。
	logger.Info("流量统计", "上行", upload, "下行", download)
}
