using System.IO;
using System.Reflection;
using System.Security.Cryptography;

namespace SshVpn.Gui.Services;

// 将内嵌的 Go 核心释放到 GUI EXE 同目录，并在版本变化时自动覆盖旧核心。
internal sealed class CorePayloadService(PortablePaths paths)
{
    private const string ResourceName = "SshVpn.Embedded.sshvpn-core.exe";

    public async Task<bool> EnsureCoreAsync()
    {
        var assembly = Assembly.GetExecutingAssembly();
        await using var hashStream = assembly.GetManifestResourceStream(ResourceName)
                                     ?? throw new InvalidOperationException("GUI 中没有找到内嵌的 Go 核心资源");
        var embeddedHash = SHA256.HashData(hashStream);

        if (File.Exists(paths.CoreExecutablePath))
        {
            try
            {
                await using var existingStream = File.OpenRead(paths.CoreExecutablePath);
                var existingHash = SHA256.HashData(existingStream);
                if (CryptographicOperations.FixedTimeEquals(embeddedHash, existingHash))
                {
                    return false;
                }
            }
            catch (IOException)
            {
                // 文件可能是旧版本或损坏文件，继续尝试原子替换。
            }
        }

        var temporaryPath = paths.CoreExecutablePath + ".tmp";
        try
        {
            await using (var resource = assembly.GetManifestResourceStream(ResourceName)
                                        ?? throw new InvalidOperationException("无法重新读取内嵌的 Go 核心资源"))
            await using (var destination = new FileStream(
                             temporaryPath,
                             FileMode.Create,
                             FileAccess.Write,
                             FileShare.None,
                             81920,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await resource.CopyToAsync(destination);
                await destination.FlushAsync();
            }
            File.Move(temporaryPath, paths.CoreExecutablePath, true);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException(
                $"释放 Go 核心失败，请确认程序目录可写且旧核心未在运行：{paths.BaseDirectory}", ex);
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
                // 主错误更重要，不用临时文件清理错误覆盖它。
            }
        }
    }
}
