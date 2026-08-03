package stats

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// 流量统计持久化文件，位于程序目录，与 network-state.json 同样的原子写模式。
const trafficStateFile = "traffic.json"

type persistedTraffic struct {
	Upload   uint64 `json:"upload"`
	Download uint64 `json:"download"`
}

// LoadTraffic 从程序目录读取累计流量；文件不存在或损坏时返回零值。
func LoadTraffic(statePath string) (upload, download uint64, err error) {
	data, err := os.ReadFile(statePath)
	if errors.Is(err, os.ErrNotExist) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, fmt.Errorf("读取流量统计失败：%w", err)
	}
	var persisted persistedTraffic
	if err := json.Unmarshal(data, &persisted); err != nil {
		// 文件损坏时不阻断启动，从零开始统计。
		return 0, 0, nil
	}
	return persisted.Upload, persisted.Download, nil
}

// SaveTraffic 把累计流量原子写入程序目录。
func SaveTraffic(statePath string, upload, download uint64) error {
	data, err := json.MarshalIndent(persistedTraffic{Upload: upload, Download: download}, "", "  ")
	if err != nil {
		return fmt.Errorf("生成流量统计失败：%w", err)
	}
	temporaryPath := statePath + ".tmp"
	if err := os.WriteFile(temporaryPath, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("保存流量统计失败：%w", err)
	}
	if err := os.Rename(temporaryPath, statePath); err != nil {
		os.Remove(temporaryPath)
		return fmt.Errorf("更新流量统计失败：%w", err)
	}
	return nil
}

// RemoveTraffic 删除持久化的流量统计（用于 -reset-traffic）。
func RemoveTraffic(statePath string) error {
	if err := os.Remove(statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("重置流量统计失败：%w", err)
	}
	return nil
}
