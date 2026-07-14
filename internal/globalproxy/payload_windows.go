//go:build windows

package globalproxy

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"io"
	"os"

	"sshvpn/internal/portable"
)

// wintunDLL 来自 https://www.wintun.net/builds/wintun-0.14.1.zip 的 amd64 版本。
// 文件拥有 WireGuard LLC 有效数字签名，运行前释放到核心 EXE 同目录。
//
//go:embed assets/wintun.dll
var wintunDLL []byte

var portableFile = portable.File

func ensureWintunDLL() (string, error) {
	path, err := portableFile("wintun.dll")
	if err != nil {
		return "", err
	}

	expectedHash := sha256.Sum256(wintunDLL)
	if file, openErr := os.Open(path); openErr == nil {
		existingHash, hashErr := io.ReadAll(file)
		file.Close()
		if hashErr == nil {
			actualHash := sha256.Sum256(existingHash)
			if bytes.Equal(expectedHash[:], actualHash[:]) {
				return path, nil
			}
		}
	} else if !os.IsNotExist(openErr) {
		return "", fmt.Errorf("检查 Wintun 组件失败：%w", openErr)
	}

	temporaryPath := path + ".tmp"
	if err := os.WriteFile(temporaryPath, wintunDLL, 0o600); err != nil {
		return "", fmt.Errorf("释放 Wintun 组件失败：%w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		os.Remove(temporaryPath)
		return "", fmt.Errorf("更新 Wintun 组件失败，请确认旧核心已经退出：%w", err)
	}
	return path, nil
}
