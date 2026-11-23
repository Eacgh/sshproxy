package stats

import (
	"context"
	"log/slog"
	"time"
)

// 周期落盘间隔。太频繁会反复写盘，太稀疏则异常退出时丢失的统计越多。
const persistInterval = 30 * time.Second

// RunPersistLoop 周期性把累计流量原子写入文件。
// 除退出时的最终落盘外，周期落盘能显著降低强杀进程时的统计丢失。
// 阻塞直到 ctx 取消。
func RunPersistLoop(ctx context.Context, statePath string, traffic *Traffic, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	ticker := time.NewTicker(persistInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			upload, download := traffic.Snapshot()
			if err := SaveTraffic(statePath, upload, download); err != nil {
				logger.Warn("定期保存流量统计失败", "错误", err)
			}
		}
	}
}
