# sshvpn 核心程序

程序连接 SSH 服务器，在本机提供 SOCKS5 代理，并可通过 Wintun 接管 Windows 全局 TCP 流量。

## 图形界面

项目提供中文 WPF 图形界面。发布包只有一个 `SshVpn.exe`；首次启动时，GUI 会把内嵌的 Go 核心释放到同目录。运行后的目录结构为：

```text
SshVpn.exe          GUI 主程序
sshvpn-core.exe     首次启动自动生成
wintun.dll          首次启用全局模式时由核心自动生成
config.json         点击“保存配置”时自动生成
known_hosts         首次成功连接时自动生成
network-state.json  全局模式运行时用于异常恢复，正常断开后删除
```

GUI 支持：

- 编辑并保存连接配置，可选填写自定义上游 DNS。
- 启动、正常停止 Go 核心并显示实时日志。
- 使用 Wintun 接管 IPv4/IPv6 TCP 流量，并通过本地 Fake-IP 把域名交给 SSH 服务器解析。
- 连接前恢复上次异常退出遗留的临时路由，断开时自动还原网络。
- 点击最小化或右上角关闭按钮时隐藏到系统托盘，通过托盘连接、断开或真正退出。
- 显示当前 SOCKS5 地址和运行状态。

程序自己的配置、核心、日志和恢复状态都只保存在 EXE 同目录，不会写入 AppData 或用户目录。程序目录必须可写，请把便携版放在桌面或自选目录，不要放入 `Program Files`。更新 `SshVpn.exe` 后，GUI 会通过哈希比较自动更新同目录的核心，不会删除已有的 `config.json` 和 `known_hosts`。

全局模式需要管理员权限，GUI 启动时会显示 Windows UAC。虚拟网卡属于内核驱动，Windows 必须把官方签名的 Wintun 驱动安装到 Driver Store，并维护必要的设备注册表状态；这是虚拟网卡工作的系统要求。程序不会把用户配置写入这些位置。

## 全局模式

GUI 默认勾选“启用全局模式（TCP）”。内部网络参数完全由程序管理；只有用户主动填写自定义 DNS 时才会增加对应的可选配置字段：

1. 建立 SSH 连接并记录服务器实际 IPv4。
2. 自动释放并加载官方 `wintun.dll 0.14.1`。
3. 为 SSH 服务器添加 `/32` 直连路由，避免隧道递归。
4. IPv4 和 IPv6 分别使用两个 `/1` 路由接管流量，不删除用户原有默认路由。
5. 自动记录当前 DNS 地址并添加临时主机路由，然后在本机返回保留范围内的 Fake-IP。默认模式不访问公共 DNS，真实域名只交给 SSH 服务器解析；自定义模式通过 SSH 查询用户指定的 DNS，但仍只向 Windows 返回 Fake-IP，并优先使用其 IPv4 结果。启用和断开时会自动清理 Windows DNS 缓存。
6. TCP 连接根据 Fake-IP 恢复域名或自定义 DNS 的真实 IPv4；绕过系统 DNS 的 HTTPS 则根据 TLS ClientHello 中公开的 SNI 回退，避免浏览器缓存的旧 Fake-IP 被发往远端。程序不会解密或修改 TLS 内容。
7. 同一目标一次只探测一条 SSH 通道，全局最多同时探测 12 个目标；目标超时后从 1 分钟开始指数延长暂停时间并合并重复日志，避免大量不可达的后台连接拖慢正在使用的网站。已经建立的连接不占探测名额，不会限制正常下载吞吐。
8. 断开时删除临时地址和路由；异常退出后在下次连接前根据 `network-state.json` 自动恢复。

当前阶段普通 UDP 会被明确阻止，不会绕过 SSH。浏览器的 QUIC 通常会自动回退到 TCP；游戏、语音通话以及依赖 UDP 的软件可能无法使用。取消勾选全局模式后，程序只提供原来的 SOCKS5 代理。

## 配置

GUI 中填写服务器、账号、密码和代理端口即可使用；如有需要也可以填写自定义上游 DNS。点击“保存配置”后自动生成 `config.json`：

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
- `dns_server`：可选字段，仅全局模式使用。GUI 留空时不会写入配置，并由 SSH 服务器解析域名；填写 DNS 的 IP 或 `IP:端口` 后，程序会通过 SSH 使用 DNS-over-TCP 查询该地址，把其 IPv4 结果保存在 Fake-IP 映射中，并向 Windows 返回空 AAAA 以兼容没有 IPv6 出口的 SSH 服务器。为避免启动时还要解析 DNS 服务器自身，此处不接受域名。

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

以管理员身份运行下面的命令可以启用全局 TCP 模式：

```text
go run ./cmd/sshvpn -config config.json -global -verbose
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

全局模式仅支持 x64 Windows。内嵌的 tun2socks 使用 MIT 许可证；预编译 Wintun DLL 使用 WireGuard LLC 随官方压缩包提供的二进制许可证，原始许可证保存在 `internal/globalproxy/assets`。
