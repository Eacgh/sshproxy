# SSH VPN（纯 Go 版）

程序通过单条可复用 SSH 连接提供本机 SOCKS5 代理，并可借助 Wintun 虚拟网卡与 gVisor 用户态协议栈在 Windows 上实现**全局 TCP 代理**或**按进程分流代理**。

整个软件已全面重构为**纯 Go 单体架构**（基于 Wails v2 + WebView2 与纯 Go Win32 系统托盘，零 C#/WPF、零 DLL 注入 Hook、零 CGO），单文件便携版仅约 17 MB。

## 图形界面

发布产物为单一绿色可执行文件 `SshVpn.exe`，全部配置、日志、密钥与 WebView2 运行目录均保存在 EXE 同目录，不写入 AppData 或其他用户目录：

```text
SshVpn.exe          纯 Go 图形主程序（内嵌核心引擎与 wintun.dll）
wintun.dll          首次启用全局或按进程分流模式时自动释放
servers.json        服务器列表（支持多条服务器）
processes.json      按进程分流白名单（可选）
traffic.json        累计流量统计（支持运行中热清零）
known_hosts         首次成功连接时自动生成（TOFU 主机密钥校验）
network-state.json  Wintun 异常退出恢复状态，正常断开后删除
logs/               每次启动生成 日期-标识.log 运行日志
.webview2/          便携版 WebView2 运行数据目录
```

GUI 支持三种互斥工作模式：

1. **按进程分流（Wintun，推荐桌面多软件场景）**：
   - 使用 Wintun + gVisor 接管流量后，通过 Windows `GetExtendedTcpTable` / `GetExtendedUdpTable` 根据连接源端口反查进程 PID 与完整路径。
   - **命中白名单的程序（包含 Edge、Chrome 等多进程浏览器的所有同名网络子进程）**：TCP 流量经 SSH 隧道转发；同时阻止其非 DNS UDP，迫使浏览器 QUIC 回退到 TCP，防止 UDP 旁路泄漏。
   - **未命中白名单的程序（如 Firefox、本地管理工具、游戏与语音）**：TCP 与 UDP 均通过 `IP_UNICAST_IF` / `IPV6_UNICAST_IF` 绑定**原物理网卡**直连出网（若遇 Fake-IP 会自动还原域名并通过物理网卡原有 DNS 解析）。
   - 在「进程分流」页支持从当前运行中程序勾选添加、浏览 `.exe` 或手动输入进程名，并在连接运行中热更新规则立即生效。
2. **全局模式（Wintun TCP）**：接管整机 IPv4/IPv6 TCP 流量并由 SSH 解析域名，阻止非 DNS UDP。
3. **仅 SOCKS5 代理**：仅在本机 `127.0.0.1:<端口>` 监听无认证 SOCKS5 代理，不创建虚拟网卡与系统路由。

其他界面特性：
- 左侧服务器列表管理多条服务器配置，右侧保存后自动遮挡锁定，点击「编辑」才显示完整参数。
- 底部实时显示累计上行/下行流量（流式实时计数），支持连接状态下免重启一键重置。
- 点击右上角关闭按钮隐藏到纯 Go Win32 系统托盘，支持托盘双击恢复、快速连接/断开或彻底退出。
- 程序目录必须可写，请放在桌面或自选目录，不要放在 `Program Files`。首次使用 Wintun 或修改路由需要管理员权限，启动时将触发 Windows UAC。

## 配置与兼容

### servers.json（多服务器列表）

```json
[
  {
    "name": "我的服务器",
    "server_address": "ssh.example.com",
    "username": "你的用户名",
    "password": "你的密码",
    "proxy_port": 1080
  }
]
```

- `name`：服务器名称，用于列表显示与 `-profile` 加载。
- `server_address`：SSH 服务器域名或 IP。未填端口默认 `22`，自定义端口写成 `ssh.example.com:2222`。
- `username` / `password`：SSH 登录凭证。
- `proxy_port`：本机 SOCKS5 监听端口（固定绑定 `127.0.0.1`），默认 `1080`。
- `dns_server`：可选字段，仅 Wintun 模式使用。留空时使用本地 Fake-IP 并把域名交给 SSH 服务器解析；填写 DNS IP 或 `IP:端口` 后通过 SSH 以 DNS-over-TCP 查询，仅向 Windows 返回 Fake-IP 与空 AAAA；按进程分流下未命中的直连程序仍使用物理网卡 DNS。

### processes.json（进程分流规则）

```json
[
  {
    "name": "msedge",
    "path": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "enabled": true
  }
]
```

向后兼容旧版不含 `enabled` 字段的 `processes.json`（缺省视为启用）。

> `servers.json` 与 `config.json` 含明文密码，已加入 `.gitignore`，切勿提交或公开。

## 命令行运行（CLI）

不使用 GUI 时可直接运行无头命令行版本 `cmd/sshvpn`：

```powershell
Copy-Item config.example.json config.json
go run ./cmd/sshvpn -config config.json
```

或从 `servers.json` 按名称加载并选择代理模式：

```powershell
# 仅本地 SOCKS5（默认）
go run ./cmd/sshvpn -profile 我的服务器

# 启用全局 TCP 模式（需管理员权限）
go run ./cmd/sshvpn -profile 我的服务器 -mode=global -verbose

# 启用按进程分流模式（读取同目录 processes.json，需管理员权限）
go run ./cmd/sshvpn -profile 我的服务器 -mode=process -verbose

# 清零累计流量统计
go run ./cmd/sshvpn -profile 我的服务器 -reset-traffic
```

## 构建（仅需 Go 1.26+）

无需安装 .NET SDK 或 Visual Studio C++ 工具链：

```powershell
# 1. 运行单元测试
go test -buildvcs=false -count=1 ./...

# 2. 更新 Windows 图标与 UAC 清单资源（如修改了 cmd/sshvpn-gui/assets/winres.json 或 app.ico）
go run github.com/tc-hib/go-winres@latest make --in cmd/sshvpn-gui/assets/winres.json --out cmd/sshvpn-gui/rsrc --arch amd64

# 3. 构建单文件便携版 GUI
go build -buildvcs=false -tags desktop,production -trimpath -ldflags="-s -w -H windowsgui" -o artifacts/sshvpn-portable/SshVpn.exe ./cmd/sshvpn-gui

# 4. （可选）构建无头命令行版本
go build -buildvcs=false -trimpath -ldflags="-s -w" -o bin/sshvpn.exe ./cmd/sshvpn
```

## 开源致谢

- 内嵌 `tun2socks` 使用 MIT 许可证；预编译官方签名 `wintun.dll 0.14.1` 许可证保存在 `internal/globalproxy/assets/WINTUN-LICENSE.txt`。
- GUI 使用 [Wails v2](https://wails.io) 与系统内置 Edge WebView2 运行时。
- 感谢 [LINUX DO](https://linux.do) 社区提供的交流与推广平台。
