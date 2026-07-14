// Package portable 统一计算便携版程序的本地文件路径。
package portable

import (
	"fmt"
	"os"
	"path/filepath"
)

// Directory 返回当前可执行文件所在目录。
// 所有持久化数据都必须以此目录为根，禁止写入 AppData 或用户目录。
func Directory() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("获取程序路径失败：%w", err)
	}
	directory := filepath.Dir(executable)
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return "", fmt.Errorf("解析程序目录失败：%w", err)
	}
	return absolute, nil
}

// File 返回与当前可执行文件同目录的文件路径。
func File(name string) (string, error) {
	directory, err := Directory()
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, name), nil
}
