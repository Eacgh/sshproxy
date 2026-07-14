using System.IO;

namespace SshVpn.Gui.Services;

// 所有路径都以 GUI EXE 所在目录为根，禁止使用 AppData、注册表或用户目录。
internal sealed class PortablePaths
{
    public string BaseDirectory { get; } = Path.GetFullPath(AppContext.BaseDirectory);

    public string ConfigPath => Path.Combine(BaseDirectory, "config.json");

    public string KnownHostsPath => Path.Combine(BaseDirectory, "known_hosts");

    public string CoreExecutablePath => Path.Combine(BaseDirectory, "sshvpn-core.exe");
}
