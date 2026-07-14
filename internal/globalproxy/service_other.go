//go:build !windows

package globalproxy

import (
	"context"
	"errors"
	"log/slog"
)

type unsupportedController struct{}

// New 在非 Windows 平台返回占位控制器，保持命令行核心可编译。
func New(Options) Controller { return unsupportedController{} }

func (unsupportedController) Start(context.Context) error {
	return errors.New("全局模式目前只支持 Windows")
}

func (unsupportedController) Close() error { return nil }

// Recover 在非 Windows 平台无需恢复系统网络状态。
func Recover(*slog.Logger) error { return nil }
