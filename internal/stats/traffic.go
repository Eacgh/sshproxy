// Package stats 统计经过代理的实际用户流量字节数。
// 统计点包括 SOCKS5 转发和全局模式转发，口径为用户数据字节，
// 不含 SSH 加密或协议开销。
package stats

import (
	"io"
	"sync/atomic"
)

const defaultCopyBufferSize = 32 << 10

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

// Reset 将累计上下行计数器原子清零，用于运行中热重置流量统计。
func (t *Traffic) Reset() {
	t.upload.Store(0)
	t.download.Store(0)
}

// CopyBuffer 从 src 向 dst 复制数据，并在每次写入成功后实时累加流量字节数。
// buffer 为空时分配默认 32 KiB 缓冲；t 为 nil 时仅执行复制。
func (t *Traffic) CopyBuffer(dst io.Writer, src io.Reader, buffer []byte, upload bool) (int64, error) {
	if len(buffer) == 0 {
		buffer = make([]byte, defaultCopyBufferSize)
	}
	writer := dst
	if t != nil {
		writer = &countingWriter{dst: dst, traffic: t, upload: upload}
	}
	return io.CopyBuffer(writer, src, buffer)
}

type countingWriter struct {
	dst     io.Writer
	traffic *Traffic
	upload  bool
}

func (w *countingWriter) Write(p []byte) (int, error) {
	written, err := w.dst.Write(p)
	if written > 0 {
		if w.upload {
			w.traffic.Add(uint64(written), 0)
		} else {
			w.traffic.Add(0, uint64(written))
		}
	}
	return written, err
}
