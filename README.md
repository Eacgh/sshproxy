# sshvpn 核心程序

程序连接 SSH 服务器，并在本机提供 SOCKS5 代理。域名由 SSH 服务器一侧解析。

## 图形界面

项目提供中文 WPF 图形界面。发布包只有一个 `SshVpn.exe`；首次启动时，GUI 会把内嵌的 Go 核心释放到同目录。运行后的目录结构为：

```text
SshVpn.exe          GUI 主程序
sshvpn-core.exe     首次启动自动生成
config.json         点击“保存配置”时自动生成
known_hosts         首次成功连接时自动生成
```

GUI 支持：

- 编辑并保存四项连接配置。
- 启动、正常停止 Go 核心并显示实时日志。
- 最小化到系统托盘，通过托盘连接、断开或退出。
- 显示当前 SOCKS5 地址和运行状态。

程序不会使用注册表、AppData 或用户目录。程序目录必须可写，请把便携版放在桌面或自选目录，不要放入 `Program Files`。更新 `SshVpn.exe` 后，GUI 会通过哈希比较自动更新同目录的核心，不会删除已有的 `config.json` 和 `known_hosts`。

## 配置

GUI 中只需填写四项，点击“保存配置”后自动生成 `config.json`：

```json
{
  "server_address": "ssh.example.com",
  "username": "你的用户名",
  "password": "你的密码",
  "proxy_port": 1080
}
```

- `server_address`：SSH 服务器域名或 IP。未填写端口时自动使用 `22`，其他端口可写成 `ssh.example.com:2222`。
- `username`：SSH 登录用户名。
- `password`：SSH 登录密码。
- `proxy_port`：本机 SOCKS5 代理端口，省略时默认使用 `1080`。

程序固定监听 `127.0.0.1`，连接超时、SSH 保活和主机密钥都由程序内部管理。首次连接时会自动记录服务器主机密钥；如果以后密钥发生变化，程序会拒绝连接并给出安全提示。

`config.json` 含有明文密码，已经被 `.gitignore` 排除。不要提交、发送或公开该文件。

## 运行

```powershell
Copy-Item config.example.json config.json
go run ./cmd/sshvpn -config config.json
```

运行期间按 `Ctrl+C` 会关闭所有本地连接和 SSH 通道后正常退出。默认只显示连接状态；需要查看每条 SOCKS5 连接时使用：

```powershell
go run ./cmd/sshvpn -config config.json -verbose
```

另一个终端使用 `curl` 验证出口 IP：

```powershell
curl.exe --proxy socks5h://127.0.0.1:1080 https://ip.me/
```

## 构建单文件 GUI

需要 Go 1.26 和 .NET 10 SDK。构建不依赖 PowerShell 脚本，顺序固定为“先核心，后 GUI”。在仓库根目录依次执行：

```text
go test -buildvcs=false ./...
go build -buildvcs=false -trimpath -ldflags="-s -w" -o gui/SshVpn.Gui/Resources/sshvpn-core.exe ./cmd/sshvpn
dotnet publish gui/SshVpn.Gui/SshVpn.Gui.csproj -p:PublishProfile=Portable
```

发布结果位于 `artifacts\sshvpn-portable\SshVpn.exe`。第一次发布可能从 NuGet 下载 .NET 单文件发布所需的运行包，仓库中的 `NuGet.Config` 会把缓存固定到 `.cache\nuget`，不会写入用户 NuGet 目录。

如果 Go 核心没有先生成，`dotnet publish` 会用中文错误明确中止，不会产出缺少核心的 GUI。

## 单独构建 Go 核心

不使用 GUI 时可以直接构建命令行版本：

```text
go build -buildvcs=false -trimpath -ldflags="-s -w" -o bin/sshvpn.exe ./cmd/sshvpn
```

当前阶段只提供 SOCKS5 代理，不会修改 Windows 系统代理、路由或 DNS。全局流量接管属于后续 TUN/Wintun 阶段。
