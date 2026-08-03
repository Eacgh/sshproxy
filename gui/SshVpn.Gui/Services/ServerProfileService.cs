using System.IO;
using System.Text;
using System.Text.Json;
using SshVpn.Gui.Models;

namespace SshVpn.Gui.Services;

// 管理多服务器列表 servers.json（程序目录）。
// 列表保存全部服务器条目；选中的服务器由 MainWindow 物化成核心读取的 config.json。
internal sealed class ServerProfileService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    private readonly PortablePaths _paths;

    public ServerProfileService(PortablePaths paths)
    {
        _paths = paths;
    }

    public string ServersPath => Path.Combine(_paths.BaseDirectory, "servers.json");

    public async Task<List<ServerProfile>> LoadAsync()
    {
        if (!File.Exists(ServersPath))
        {
            return new List<ServerProfile>();
        }
        try
        {
            await using var stream = File.OpenRead(ServersPath);
            var list = await JsonSerializer.DeserializeAsync<List<ServerProfile>>(stream, JsonOptions);
            return list ?? new List<ServerProfile>();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            throw new InvalidOperationException($"读取服务器列表失败：{ex.Message}", ex);
        }
    }

    public async Task SaveAsync(List<ServerProfile> profiles)
    {
        var temporaryPath = ServersPath + ".tmp";
        try
        {
            var json = JsonSerializer.Serialize(profiles, JsonOptions) + Environment.NewLine;
            await File.WriteAllTextAsync(temporaryPath, json, new UTF8Encoding(false));
            File.Move(temporaryPath, ServersPath, true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException(
                $"保存服务器列表失败，请确认程序目录可写：{_paths.BaseDirectory}", ex);
        }
        finally
        {
            try
            {
                if (File.Exists(temporaryPath))
                {
                    File.Delete(temporaryPath);
                }
            }
            catch (IOException)
            {
                // 主错误已在界面显示，清理失败不覆盖原始原因。
            }
        }
    }

    // FromAppConfig 由现有 config.json 生成一个默认服务器条目（旧版升级兼容）。
    public static ServerProfile FromAppConfig(AppConfig config)
    {
        return new ServerProfile
        {
            Name = string.IsNullOrWhiteSpace(config.ServerAddress) ? "服务器 1" : config.ServerAddress,
            ServerAddress = config.ServerAddress,
            Username = config.Username,
            Password = config.Password,
            ProxyPort = config.ProxyPort,
            DnsServer = config.DnsServer
        };
    }

    // ToAppConfig 把服务器条目物化成核心读取的配置。
    public static AppConfig ToAppConfig(ServerProfile profile)
    {
        return new AppConfig
        {
            ServerAddress = profile.ServerAddress,
            Username = profile.Username,
            Password = profile.Password,
            ProxyPort = profile.ProxyPort,
            DnsServer = profile.DnsServer
        };
    }
}
