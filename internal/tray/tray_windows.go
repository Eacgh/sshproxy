//go:build windows

// Package tray 提供基于 Win32 Shell_NotifyIconW 的纯 Go 系统托盘实现。
package tray

import (
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wmDestroy     = 0x0002
	wmClose       = 0x0010
	wmCommand     = 0x0111
	wmNull        = 0x0000
	wmLButtonDbl  = 0x0203
	wmRButtonUp   = 0x0205
	wmApp         = 0x8000
	wmTrayIcon    = wmApp + 1
	wmUpdateTray  = wmApp + 2
	wmDestroyTray = wmApp + 3

	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004
	nimAdd     = 0x00000000
	nimModify  = 0x00000001
	nimDelete  = 0x00000002

	mfString    = 0x00000000
	mfSeparator = 0x00000800
	tpmLeftAlign   = 0x0000
	tpmRightButton = 0x0002
	tpmBottomAlign = 0x0020

	idiShield = 32518

	menuIDShow   = 1001
	menuIDToggle = 1002
	menuIDExit   = 1003
)

var (
	user32DLL              = windows.NewLazySystemDLL("user32.dll")
	shell32DLL             = windows.NewLazySystemDLL("shell32.dll")
	procRegisterClassExW   = user32DLL.NewProc("RegisterClassExW")
	procCreateWindowExW    = user32DLL.NewProc("CreateWindowExW")
	procDefWindowProcW     = user32DLL.NewProc("DefWindowProcW")
	procDestroyWindow      = user32DLL.NewProc("DestroyWindow")
	procGetMessageW        = user32DLL.NewProc("GetMessageW")
	procTranslateMessage   = user32DLL.NewProc("TranslateMessage")
	procDispatchMessageW   = user32DLL.NewProc("DispatchMessageW")
	procPostMessageW       = user32DLL.NewProc("PostMessageW")
	procPostQuitMessage    = user32DLL.NewProc("PostQuitMessage")
	procLoadIconW          = user32DLL.NewProc("LoadIconW")
	procCreatePopupMenu    = user32DLL.NewProc("CreatePopupMenu")
	procAppendMenuW        = user32DLL.NewProc("AppendMenuW")
	procTrackPopupMenu     = user32DLL.NewProc("TrackPopupMenu")
	procDestroyMenu        = user32DLL.NewProc("DestroyMenu")
	procSetForegroundWin   = user32DLL.NewProc("SetForegroundWindow")
	procGetCursorPos       = user32DLL.NewProc("GetCursorPos")
	procShellNotifyIconW   = shell32DLL.NewProc("Shell_NotifyIconW")
)

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     windows.Handle
	hIcon         windows.Handle
	hCursor       windows.Handle
	hbrBackground windows.Handle
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       windows.Handle
}

type point struct {
	x int32
	y int32
}

type winMsg struct {
	hwnd     windows.Handle
	message  uint32
	wParam   uintptr
	lParam   uintptr
	time     uint32
	pt       point
	lPrivate uint32
}

type notifyIconDataW struct {
	cbSize           uint32
	hWnd             windows.Handle
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            windows.Handle
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         windows.GUID
	hBalloonIcon     windows.Handle
}

// Callbacks 定义托盘用户操作回调。
type Callbacks struct {
	OnShow   func()
	OnToggle func()
	OnExit   func()
}

// Tray 管理 Windows 系统托盘图标及右键菜单。
type Tray struct {
	callbacks Callbacks

	mu         sync.Mutex
	hwnd       windows.Handle
	tooltip    string
	toggleText string
	closed     bool

	ready chan struct{}
	done  chan struct{}
}

// Start 启动系统托盘后台消息循环并立即创建托盘图标。
func Start(initialTooltip string, callbacks Callbacks) *Tray {
	if initialTooltip == "" {
		initialTooltip = "SSH VPN - 未连接"
	}
	t := &Tray{
		callbacks:  callbacks,
		tooltip:    initialTooltip,
		toggleText: "连接",
		ready:      make(chan struct{}),
		done:       make(chan struct{}),
	}
	go t.run()
	<-t.ready
	return t
}

// SetStatus 更新托盘提示文本以及菜单中的“连接/断开”按钮文字。
func (t *Tray) SetStatus(tooltip string, canDisconnect bool) {
	if t == nil {
		return
	}
	toggleText := "连接"
	if canDisconnect {
		toggleText = "断开"
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.tooltip = tooltip
	t.toggleText = toggleText
	hwnd := t.hwnd
	t.mu.Unlock()

	if hwnd != 0 {
		_, _, _ = procPostMessageW.Call(uintptr(hwnd), wmUpdateTray, 0, 0)
	}
}

// Close 移除托盘图标并退出 Win32 消息循环。
func (t *Tray) Close() {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		<-t.done
		return
	}
	t.closed = true
	hwnd := t.hwnd
	t.mu.Unlock()

	if hwnd != 0 {
		_, _, _ = procPostMessageW.Call(uintptr(hwnd), wmDestroyTray, 0, 0)
	}
	<-t.done
}

func (t *Tray) run() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(t.done)

	var hInstance windows.Handle
	_ = windows.GetModuleHandleEx(0, nil, &hInstance)

	icon := loadAppIcon(hInstance)
	className := windows.StringToUTF16Ptr("SshVpnTrayWindowClass")
	wndProc := syscall.NewCallback(t.wndProc)

	wc := wndClassExW{
		cbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		lpfnWndProc:   wndProc,
		hInstance:     hInstance,
		hIcon:         icon,
		lpszClassName: className,
	}
	_, _, _ = procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	hwndRaw, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("SshVpnTray"))),
		0,
		0, 0, 0, 0,
		0, 0, uintptr(hInstance), 0,
	)
	hwnd := windows.Handle(hwndRaw)
	t.mu.Lock()
	t.hwnd = hwnd
	t.mu.Unlock()
	close(t.ready)

	if hwnd == 0 {
		return
	}

	t.notifyIcon(hwnd, icon, nimAdd)

	var msg winMsg
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
	t.notifyIcon(hwnd, icon, nimDelete)
}

func (t *Tray) wndProc(hwnd windows.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmTrayIcon:
		switch uint32(lParam) {
		case wmLButtonDbl:
			if t.callbacks.OnShow != nil {
				go t.callbacks.OnShow()
			}
		case wmRButtonUp:
			t.showMenu(hwnd)
		}
		return 0
	case wmUpdateTray:
		var hInstance windows.Handle
		_ = windows.GetModuleHandleEx(0, nil, &hInstance)
		t.notifyIcon(hwnd, loadAppIcon(hInstance), nimModify)
		return 0
	case wmDestroyTray, wmClose:
		t.notifyIcon(hwnd, 0, nimDelete)
		_, _, _ = procDestroyWindow.Call(uintptr(hwnd))
		return 0
	case wmDestroy:
		_, _, _ = procPostQuitMessage.Call(0)
		return 0
	case wmCommand:
		switch uint32(wParam) & 0xFFFF {
		case menuIDShow:
			if t.callbacks.OnShow != nil {
				go t.callbacks.OnShow()
			}
		case menuIDToggle:
			if t.callbacks.OnToggle != nil {
				go t.callbacks.OnToggle()
			}
		case menuIDExit:
			if t.callbacks.OnExit != nil {
				go t.callbacks.OnExit()
			}
		}
		return 0
	}
	ret, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return ret
}

func (t *Tray) notifyIcon(hwnd, icon windows.Handle, action uint32) {
	t.mu.Lock()
	tooltip := t.tooltip
	t.mu.Unlock()

	var nid notifyIconDataW
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = hwnd
	nid.uID = 1
	nid.uFlags = nifMessage | nifTip
	nid.uCallbackMessage = wmTrayIcon
	if icon != 0 {
		nid.uFlags |= nifIcon
		nid.hIcon = icon
	}
	tipUTF16, _ := windows.UTF16FromString(tooltip)
	copy(nid.szTip[:len(nid.szTip)-1], tipUTF16)
	_, _, _ = procShellNotifyIconW.Call(uintptr(action), uintptr(unsafe.Pointer(&nid)))
}

func (t *Tray) showMenu(hwnd windows.Handle) {
	t.mu.Lock()
	toggleText := t.toggleText
	t.mu.Unlock()

	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)

	_, _, _ = procAppendMenuW.Call(menu, mfString, menuIDShow, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("显示窗口"))))
	_, _, _ = procAppendMenuW.Call(menu, mfString, menuIDToggle, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(toggleText))))
	_, _, _ = procAppendMenuW.Call(menu, mfSeparator, 0, 0)
	_, _, _ = procAppendMenuW.Call(menu, mfString, menuIDExit, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("退出"))))

	var pt point
	_, _, _ = procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	_, _, _ = procSetForegroundWin.Call(uintptr(hwnd))
	_, _, _ = procTrackPopupMenu.Call(menu, tpmLeftAlign|tpmRightButton|tpmBottomAlign, uintptr(pt.x), uintptr(pt.y), 0, uintptr(hwnd), 0)
	_, _, _ = procPostMessageW.Call(uintptr(hwnd), wmNull, 0, 0)
}

func loadAppIcon(hInstance windows.Handle) windows.Handle {
	if hInstance != 0 {
		icon, _, _ := procLoadIconW.Call(uintptr(hInstance), 1)
		if icon != 0 {
			return windows.Handle(icon)
		}
	}
	fallback, _, _ := procLoadIconW.Call(0, idiShield)
	return windows.Handle(fallback)
}
