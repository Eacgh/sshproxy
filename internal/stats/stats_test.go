package stats

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTrafficAddAndSnapshot(t *testing.T) {
	traffic := new(Traffic)
	traffic.Add(100, 200)
	traffic.Add(50, 25)
	upload, download := traffic.Snapshot()
	if upload != 150 || download != 225 {
		t.Fatalf("累计值 = %d/%d，期望 150/225", upload, download)
	}
}

func TestTrafficRestore(t *testing.T) {
	traffic := new(Traffic)
	traffic.Restore(1000, 2000)
	upload, download := traffic.Snapshot()
	if upload != 1000 || download != 2000 {
		t.Fatalf("恢复值 = %d/%d，期望 1000/2000", upload, download)
	}
	// Restore 后继续累加。
	traffic.Add(1, 2)
	upload, download = traffic.Snapshot()
	if upload != 1001 || download != 2002 {
		t.Fatalf("恢复后累加 = %d/%d", upload, download)
	}
}

func TestPersistRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	if err := SaveTraffic(path, 1234, 5678); err != nil {
		t.Fatal(err)
	}
	upload, download, err := LoadTraffic(path)
	if err != nil {
		t.Fatal(err)
	}
	if upload != 1234 || download != 5678 {
		t.Fatalf("往返后 = %d/%d，期望 1234/5678", upload, download)
	}
}

func TestLoadTrafficMissingFileReturnsZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent.json")
	upload, download, err := LoadTraffic(path)
	if err != nil {
		t.Fatal(err)
	}
	if upload != 0 || download != 0 {
		t.Fatalf("缺失文件应返回零值，实际 %d/%d", upload, download)
	}
}

func TestLoadTrafficCorruptFileReturnsZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	upload, download, err := LoadTraffic(path)
	if err != nil {
		t.Fatal(err)
	}
	if upload != 0 || download != 0 {
		t.Fatalf("损坏文件应返回零值，实际 %d/%d", upload, download)
	}
}

func TestRemoveTraffic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	if err := SaveTraffic(path, 1, 2); err != nil {
		t.Fatal(err)
	}
	if err := RemoveTraffic(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("重置后文件仍存在：%v", err)
	}
	// 删除不存在的文件不应报错。
	if err := RemoveTraffic(path); err != nil {
		t.Fatalf("删除不存在文件应成功：%v", err)
	}
}

func TestRunReporterOutputsTraffic(t *testing.T) {
	traffic := new(Traffic)
	traffic.Restore(1024, 2048)
	var output string
	logger := slog.New(slog.NewTextHandler(&writeRecorder{write: func(p []byte) { output += string(p) }}, nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunReporter(ctx, traffic, logger)
	}()
	// 等待至少两次输出，再取消。
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(output) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if output == "" {
		t.Fatal("reporter 没有输出任何日志")
	}
	if len(output) < 10 || !containsTraffic(output) {
		t.Fatalf("reporter 输出不包含流量统计：%q", output)
	}
}

type writeRecorder struct {
	write func([]byte)
}

func (w *writeRecorder) Write(p []byte) (int, error) {
	w.write(p)
	return len(p), nil
}

func containsTraffic(output string) bool {
	for _, keyword := range []string{"流量统计", "上行", "下行"} {
		found := false
		for i := 0; i+len(keyword) <= len(output); i++ {
			if output[i:i+len(keyword)] == keyword {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func TestCopyBufferAccountsTrafficBeforeClose(t *testing.T) {
	traffic := new(Traffic)
	srcWriter, srcReader := net.Pipe()
	dstReader, dstWriter := net.Pipe()
	defer srcWriter.Close()
	defer srcReader.Close()
	defer dstReader.Close()
	defer dstWriter.Close()

	copyDone := make(chan error, 1)
	go func() {
		_, err := traffic.CopyBuffer(dstWriter, srcReader, make([]byte, 1024), true)
		copyDone <- err
	}()

	payload := []byte("streaming-upload-chunk")
	writeDone := make(chan error, 1)
	go func() {
		_, err := srcWriter.Write(payload)
		writeDone <- err
	}()

	received := make([]byte, len(payload))
	if _, err := io.ReadFull(dstReader, received); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}

	// 连接尚未关闭，实时统计就已经完成累加。
	deadline := time.Now().Add(time.Second)
	for {
		upload, download := traffic.Snapshot()
		if upload == uint64(len(payload)) && download == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("连接未关闭时流量未实时累加：upload=%d download=%d", upload, download)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// 下行方向同样在未关闭时实时记账。
	dlSrcWriter, dlSrcReader := net.Pipe()
	dlDstReader, dlDstWriter := net.Pipe()
	defer dlSrcWriter.Close()
	defer dlSrcReader.Close()
	defer dlDstReader.Close()
	defer dlDstWriter.Close()

	dlDone := make(chan error, 1)
	go func() {
		_, err := traffic.CopyBuffer(dlDstWriter, dlSrcReader, nil, false)
		dlDone <- err
	}()
	dlPayload := []byte("download-chunk")
	go func() { _, _ = dlSrcWriter.Write(dlPayload) }()
	if _, err := io.ReadFull(dlDstReader, make([]byte, len(dlPayload))); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(time.Second)
	for {
		_, download := traffic.Snapshot()
		if download == uint64(len(dlPayload)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("下行流量未实时累加：download=%d", download)
		}
		time.Sleep(5 * time.Millisecond)
	}

	srcWriter.Close()
	dlSrcWriter.Close()
	if err := <-copyDone; err != nil {
		t.Fatalf("上行 CopyBuffer 返回错误：%v", err)
	}
	if err := <-dlDone; err != nil {
		t.Fatalf("下行 CopyBuffer 返回错误：%v", err)
	}
}
