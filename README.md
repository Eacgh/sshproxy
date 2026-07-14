# sshvpn 核心程序

程序连接 SSH 服务器，并在本机提供 SOCKS5 代理。域名由 SSH 服务器一侧解析。

## 配置

复制 `config.example.json` 为 `config.json`，只需填写四项：

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

`config.json` 含有明文密码，已经被 `.gitignore` 排除。不要提交、发送或公开该文件。后续接入 C# GUI 时应把密码迁移到 Windows 凭据管理器。

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

## 构建与测试

```powershell
go test -buildvcs=false ./...
go build -buildvcs=false -o bin/sshvpn.exe ./cmd/sshvpn
```

当前阶段只提供 SOCKS5 代理，不会修改 Windows 系统代理、路由或 DNS。全局流量接管属于后续 TUN/Wintun 阶段。
