package main

import (
	"embed"
	"io/fs"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend
var frontendEmbed embed.FS

func main() {
	frontendFS, err := fs.Sub(frontendEmbed, "frontend")
	if err != nil {
		println("加载前端资源失败:", err.Error())
		os.Exit(1)
	}

	app, err := NewApp()
	if err != nil {
		println("初始化 SSH VPN 失败:", err.Error())
		os.Exit(1)
	}

	err = wails.Run(&options.App{
		Title:     "SSH VPN",
		Width:     900,
		Height:    720,
		MinWidth:  740,
		MinHeight: 580,
		BackgroundColour: &options.RGBA{
			R: 246,
			G: 248,
			B: 249,
			A: 255,
		},
		AssetServer: &assetserver.Options{
			Assets: frontendFS,
		},
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: "sshvpn.portable.singleinstance.v1",
			OnSecondInstanceLaunch: func(options.SecondInstanceData) {
				app.ShowWindow()
			},
		},
		Windows: &windows.Options{
			WebviewUserDataPath: app.WebviewUserDataPath(),
		},
		OnStartup:     app.OnStartup,
		OnBeforeClose: app.OnBeforeClose,
		OnShutdown:    app.OnShutdown,
		Bind: []any{
			app,
		},
	})
	if err != nil {
		println("启动 SSH VPN 失败:", err.Error())
		os.Exit(1)
	}
}
