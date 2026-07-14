//go:build windows

package globalproxy

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureWintunDLLWritesAndRepairsPayload(t *testing.T) {
	directory := t.TempDir()
	previousPortableFile := portableFile
	portableFile = func(name string) (string, error) { return filepath.Join(directory, name), nil }
	t.Cleanup(func() { portableFile = previousPortableFile })

	path, err := ensureWintunDLL()
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, wintunDLL) {
		t.Fatal("首次释放的 Wintun 内容不正确")
	}

	if err := os.WriteFile(path, []byte("损坏"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureWintunDLL(); err != nil {
		t.Fatal(err)
	}
	content, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, wintunDLL) {
		t.Fatal("损坏的 Wintun 没有被自动修复")
	}
}
