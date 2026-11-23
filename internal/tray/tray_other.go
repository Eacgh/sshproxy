//go:build !windows

package tray

// Callbacks 定义托盘用户操作回调（非 Windows 平台占位定义）。
type Callbacks struct {
	OnShow   func()
	OnToggle func()
	OnExit   func()
}

// Tray 在非 Windows 平台为空实现，保持包可跨平台编译。
type Tray struct{}

func Start(string, Callbacks) *Tray { return &Tray{} }
func (*Tray) SetStatus(string, bool) {}
func (*Tray) Close()                 {}
