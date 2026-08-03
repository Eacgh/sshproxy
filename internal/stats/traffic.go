// Package stats 统计经过代理的实际用户流量字节数。
// 统计点包括 SOCKS5 转发和全局模式转发，口径为用户数据字节，
// 不含 SSH 加密或协议开销。
package stats

import "sync/atomic"

// Traffic 保存累计的上下行字节数。
// 上行 = 本机发往远端（客户端上传），下行 = 远端发往本机（下载）。
type Traffic struct {
	upload   atomic.Uint64
	download atomic.Uint64
}

// Add 累加一次传输的上下行字节数。
func (t *Traffic) Add(upload, download uint64) {
	t.upload.Add(upload)
	t.download.Add(download)
}

// Snapshot 返回当前累计值。
func (t *Traffic) Snapshot() (upload, download uint64) {
	return t.upload.Load(), t.download.Load()
}

// Restore 把持久化加载的累计值写入计数器（仅在启动时调用一次）。
func (t *Traffic) Restore(upload, download uint64) {
	t.upload.Store(upload)
	t.download.Store(download)
}
