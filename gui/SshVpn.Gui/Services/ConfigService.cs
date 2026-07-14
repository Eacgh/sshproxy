using System.IO;
using System.Text;
using System.Text.Json;
using SshVpn.Gui.Models;

namespace SshVpn.Gui.Services;

internal sealed class ConfigService(PortablePaths paths)
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    public async Task<AppConfig> LoadAsync()
    {
        if (!File.Exists(paths.ConfigPath))
        {
            return new AppConfig();
        }

        try
        {
            await using var stream = File.OpenRead(paths.ConfigPath);
            return await JsonSerializer.DeserializeAsync<AppConfig>(stream, JsonOptions)
                   ?? new AppConfig();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            throw new InvalidOperationException($"读取配置失败：{ex.Message}", ex);
        }
    }

    public async Task SaveAsync(AppConfig config)
    {
        var temporaryPath = paths.ConfigPath + ".tmp";
        try
        {
            var json = JsonSerializer.Serialize(config, JsonOptions) + Environment.NewLine;
            await File.WriteAllTextAsync(temporaryPath, json, new UTF8Encoding(false));
            File.Move(temporaryPath, paths.ConfigPath, true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException(
                $"保存配置失败，请确认程序目录可写：{paths.BaseDirectory}", ex);
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
}
