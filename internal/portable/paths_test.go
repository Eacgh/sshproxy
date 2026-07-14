package portable

import (
	"path/filepath"
	"testing"
)

func TestFileUsesExecutableDirectory(t *testing.T) {
	directory, err := Directory()
	if err != nil {
		t.Fatal(err)
	}
	path, err := File("config.json")
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(directory, "config.json") {
		t.Fatalf("便携文件路径为 %q", path)
	}
}
