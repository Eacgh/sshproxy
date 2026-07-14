using System.Diagnostics;
using System.IO;
using System.Text;

namespace SshVpn.Gui.Services;

internal enum CoreState
{
    Stopped,
    Starting,
    Connected,
    Stopping,
    Faulted
}

internal sealed class CoreProcessService(PortablePaths paths) : IAsyncDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Process? _process;
    private bool _intentionalStop;

    public CoreState State { get; private set; } = CoreState.Stopped;

    public event EventHandler<string>? LogReceived;

    public event EventHandler<CoreState>? StateChanged;

    public async Task StartAsync()
    {
        await _gate.WaitAsync();
        try
        {
            if (_process is { HasExited: false })
            {
                return;
            }
            if (!File.Exists(paths.CoreExecutablePath))
            {
                throw new FileNotFoundException("找不到 Go 核心程序", paths.CoreExecutablePath);
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = paths.CoreExecutablePath,
                WorkingDirectory = paths.BaseDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            startInfo.ArgumentList.Add("-config");
            startInfo.ArgumentList.Add(paths.ConfigPath);
            startInfo.ArgumentList.Add("-verbose");
            startInfo.ArgumentList.Add("-control-stdin");

            var process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
            process.OutputDataReceived += HandleOutput;
            process.ErrorDataReceived += HandleOutput;
            process.Exited += HandleExited;

            _intentionalStop = false;
            _process = process;
            SetState(CoreState.Starting);
            if (!process.Start())
            {
                throw new InvalidOperationException("Go 核心程序启动失败");
            }
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            EmitLog("Go 核心程序已启动");
        }
        catch
        {
            var failedProcess = _process;
            _process = null;
            if (failedProcess is not null)
            {
                try
                {
                    if (!failedProcess.HasExited)
                    {
                        failedProcess.Kill(true);
                        await failedProcess.WaitForExitAsync();
                    }
                }
                catch (InvalidOperationException)
                {
                    // 进程可能恰好在检查后退出。
                }
                finally
                {
                    failedProcess.Dispose();
                }
            }
            SetState(CoreState.Faulted);
            throw;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task StopAsync()
    {
        await _gate.WaitAsync();
        try
        {
            var process = _process;
            if (process is null || process.HasExited)
            {
                _process = null;
                SetState(CoreState.Stopped);
                return;
            }

            _intentionalStop = true;
            SetState(CoreState.Stopping);
            EmitLog("正在通知 Go 核心正常退出");
            try
            {
                await process.StandardInput.WriteLineAsync("stop");
                await process.StandardInput.FlushAsync();
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await process.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException)
            {
                EmitLog("正常退出超时，正在结束核心进程");
                process.Kill(true);
                await process.WaitForExitAsync();
            }
            catch (IOException)
            {
                if (!process.HasExited)
                {
                    process.Kill(true);
                    await process.WaitForExitAsync();
                }
            }

            if (ReferenceEquals(_process, process))
            {
                _process = null;
            }
            process.Dispose();
            SetState(CoreState.Stopped);
        }
        finally
        {
            _gate.Release();
        }
    }

    private void HandleOutput(object sender, DataReceivedEventArgs args)
    {
        if (string.IsNullOrWhiteSpace(args.Data))
        {
            return;
        }
        EmitLog(args.Data);
        if (args.Data.Contains("SOCKS5 代理已开始监听", StringComparison.Ordinal))
        {
            SetState(CoreState.Connected);
        }
    }

    private void HandleExited(object? sender, EventArgs args)
    {
        if (sender is not Process process)
        {
            return;
        }

        var exitCode = process.ExitCode;
        EmitLog($"Go 核心程序已退出，代码：{exitCode}");
        if (ReferenceEquals(_process, process))
        {
            _process = null;
            SetState(_intentionalStop || exitCode == 0 ? CoreState.Stopped : CoreState.Faulted);
        }
    }

    private void EmitLog(string message) => LogReceived?.Invoke(this, message);

    private void SetState(CoreState state)
    {
        if (State == state)
        {
            return;
        }
        State = state;
        StateChanged?.Invoke(this, state);
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        _gate.Dispose();
    }
}
