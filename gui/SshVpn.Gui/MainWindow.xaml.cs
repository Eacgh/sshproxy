using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Windows;
using System.Windows.Media;
using SshVpn.Gui.Models;
using SshVpn.Gui.Services;
using DrawingSystemIcons = System.Drawing.SystemIcons;
using Forms = System.Windows.Forms;

namespace SshVpn.Gui;

public partial class MainWindow : Window
{
    private readonly PortablePaths _paths = new();
    private readonly ConfigService _configService;
    private readonly CorePayloadService _corePayloadService;
    private readonly CoreProcessService _coreService;
    private readonly Forms.NotifyIcon _trayIcon;
    private readonly Forms.ToolStripMenuItem _trayToggleItem;
    private bool _syncingPassword;
    private bool _exitRequested;
    private bool _allowClose;
    private bool _closing;
    private bool _windowLoaded;

    public MainWindow()
    {
        InitializeComponent();
        _configService = new ConfigService(_paths);
        _corePayloadService = new CorePayloadService(_paths);
        _coreService = new CoreProcessService(_paths);
        _coreService.LogReceived += CoreService_LogReceived;
        _coreService.StateChanged += CoreService_StateChanged;

        _trayToggleItem = new Forms.ToolStripMenuItem("连接", null, (_, _) => Dispatcher.InvokeAsync(ToggleConnectionAsync));
        var trayMenu = new Forms.ContextMenuStrip();
        trayMenu.Items.Add("显示窗口", null, (_, _) => Dispatcher.Invoke(ShowFromTray));
        trayMenu.Items.Add(_trayToggleItem);
        trayMenu.Items.Add(new Forms.ToolStripSeparator());
        trayMenu.Items.Add("退出", null, (_, _) => Dispatcher.Invoke(RequestExit));
        _trayIcon = new Forms.NotifyIcon
        {
            Icon = DrawingSystemIcons.Shield,
            Text = "SSH VPN - 未连接",
            ContextMenuStrip = trayMenu,
            Visible = true
        };
        _trayIcon.DoubleClick += (_, _) => Dispatcher.Invoke(ShowFromTray);

        DataDirectoryText.Text = _paths.BaseDirectory;
        Loaded += MainWindow_Loaded;
        UpdateState(CoreState.Stopped);
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        _windowLoaded = true;
        try
        {
            var coreUpdated = await _corePayloadService.EnsureCoreAsync();
            AddLog(coreUpdated ? "Go 核心已从 GUI 自动释放或更新" : "Go 核心已就绪");

            var config = await _configService.LoadAsync();
            ServerAddressBox.Text = config.ServerAddress;
            UsernameBox.Text = config.Username;
            PasswordInput.Password = config.Password;
            ProxyPortBox.Text = config.ProxyPort.ToString();
            DnsServerBox.Text = config.DnsServer ?? string.Empty;
            UpdateEndpointText(config.ProxyPort);
            AddLog(File.Exists(_paths.ConfigPath) ? "已读取同目录配置" : "尚未创建配置文件");
        }
        catch (Exception ex)
        {
            ShowValidation(ex.Message);
            AddLog(ex.Message);
        }

    }

    private async void SaveButton_Click(object sender, RoutedEventArgs e)
    {
        await SaveConfigAsync();
    }

    private async void ConnectButton_Click(object sender, RoutedEventArgs e)
    {
        await ToggleConnectionAsync();
    }

    private async Task ToggleConnectionAsync()
    {
        try
        {
            if (_coreService.State is CoreState.Starting or CoreState.Connected)
            {
                await _coreService.StopAsync();
                return;
            }
            if (_coreService.State == CoreState.Stopping)
            {
                return;
            }
            if (!await SaveConfigAsync())
            {
                return;
            }
            await _coreService.StartAsync(GlobalModeCheckBox.IsChecked == true);
        }
        catch (Exception ex)
        {
            ShowValidation(ex.Message);
            AddLog(ex.Message);
        }
    }

    private async Task<bool> SaveConfigAsync()
    {
        HideValidation();
        if (string.IsNullOrWhiteSpace(ServerAddressBox.Text))
        {
            ShowValidation("请填写服务器地址");
            return false;
        }
        if (string.IsNullOrWhiteSpace(UsernameBox.Text))
        {
            ShowValidation("请填写用户名");
            return false;
        }
        var password = ShowPasswordCheckBox.IsChecked == true
            ? VisiblePasswordInput.Text
            : PasswordInput.Password;
        if (string.IsNullOrEmpty(password))
        {
            ShowValidation("请填写密码");
            return false;
        }
        if (!int.TryParse(ProxyPortBox.Text, out var proxyPort) || proxyPort is < 1 or > 65535)
        {
            ShowValidation("代理端口必须在 1 到 65535 之间");
            return false;
        }
        var dnsServer = DnsServerBox.Text.Trim();
        if (!IsValidDnsServer(dnsServer))
        {
            ShowValidation("自定义 DNS 必须填写 IP 或 IP:端口；留空则使用 Fake-IP");
            return false;
        }

        var config = new AppConfig
        {
            ServerAddress = ServerAddressBox.Text.Trim(),
            Username = UsernameBox.Text.Trim(),
            Password = password,
            ProxyPort = proxyPort,
            DnsServer = string.IsNullOrEmpty(dnsServer) ? null : dnsServer
        };
        await _configService.SaveAsync(config);
        UpdateEndpointText(proxyPort);
        AddLog("配置已保存到程序目录");
        return true;
    }

    private static bool IsValidDnsServer(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || IPAddress.TryParse(value.Trim('[', ']'), out _))
        {
            return true;
        }
        return IPEndPoint.TryParse(value, out var endpoint) && endpoint.Port is >= 1 and <= 65535;
    }

    private void CoreService_LogReceived(object? sender, string message)
    {
        Dispatcher.InvokeAsync(() => AddLog(message));
    }

    private void CoreService_StateChanged(object? sender, CoreState state)
    {
        Dispatcher.InvokeAsync(() => UpdateState(state));
    }

    private void UpdateState(CoreState state)
    {
        var (text, color) = state switch
        {
            CoreState.Starting => ("正在连接", "#D97706"),
            CoreState.Connected when _coreService.GlobalMode => ("已连接（全局 TCP）", "#07835C"),
            CoreState.Connected => ("已连接（SOCKS5）", "#07835C"),
            CoreState.Stopping => ("正在断开", "#D97706"),
            CoreState.Faulted => ("连接失败", "#B42318"),
            _ => ("未连接", "#8A969C")
        };
        StatusText.Text = text;
        StatusDot.Fill = (System.Windows.Media.Brush)new BrushConverter().ConvertFromString(color)!;
        _trayIcon.Text = $"SSH VPN - {text}";

        var running = state is CoreState.Starting or CoreState.Connected or CoreState.Stopping;
        ServerAddressBox.IsEnabled = !running;
        UsernameBox.IsEnabled = !running;
        PasswordInput.IsEnabled = !running;
        VisiblePasswordInput.IsEnabled = !running;
        ProxyPortBox.IsEnabled = !running;
        DnsServerBox.IsEnabled = !running;
        ShowPasswordCheckBox.IsEnabled = !running;
        GlobalModeCheckBox.IsEnabled = !running;
        SaveButton.IsEnabled = !running;
        ConnectButton.IsEnabled = state != CoreState.Stopping;

        var canDisconnect = state is CoreState.Starting or CoreState.Connected;
        ConnectButtonText.Text = canDisconnect ? "断开" : "连接";
        ConnectButtonIcon.Text = canDisconnect ? "\uE71A" : "\uE768";
        _trayToggleItem.Text = canDisconnect ? "断开" : "连接";
        if (state == CoreState.Faulted)
        {
            ShowValidation("连接失败，详细原因已显示在日志页");
            MainTabs.SelectedItem = LogTab;
        }
    }

    private void UpdateEndpointText(int proxyPort)
    {
        EndpointText.Text = GlobalModeCheckBox.IsChecked == true
            ? $"全局 TCP · SOCKS5 127.0.0.1:{proxyPort}"
            : $"SOCKS5 127.0.0.1:{proxyPort}";
    }

    private void AddLog(string message)
    {
        var line = $"{DateTime.Now:HH:mm:ss}  {FormatLogMessage(message)}";
        LogList.Items.Add(line);
        while (LogList.Items.Count > 1000)
        {
            LogList.Items.RemoveAt(0);
        }
        LogList.ScrollIntoView(LogList.Items[^1]);
    }

    // Go slog 已经包含完整 ISO 时间；GUI 保留自己的短时间并压缩重复字段。
    private static string FormatLogMessage(string message)
    {
        if (!message.StartsWith("时间=", StringComparison.Ordinal))
        {
            return message;
        }

        const string levelMarker = " 级别=";
        const string messageMarker = " 消息=";
        var levelStart = message.IndexOf(levelMarker, StringComparison.Ordinal);
        var messageStart = message.IndexOf(messageMarker, StringComparison.Ordinal);
        if (levelStart < 0 || messageStart <= levelStart)
        {
            return message;
        }

        var level = message[(levelStart + levelMarker.Length)..messageStart];
        var payload = message[(messageStart + messageMarker.Length)..];
        if (payload.StartsWith('"'))
        {
            var closingQuote = payload.IndexOf('"', 1);
            if (closingQuote > 0)
            {
                payload = payload[1..closingQuote] + payload[(closingQuote + 1)..];
            }
        }
        return $"[{level}] {payload.TrimStart()}";
    }

    private void ClearLogsButton_Click(object sender, RoutedEventArgs e) => LogList.Items.Clear();

    private void CopyLogsButton_Click(object sender, RoutedEventArgs e)
    {
        if (LogList.Items.Count == 0)
        {
            return;
        }
        var text = string.Join(Environment.NewLine, LogList.Items.Cast<string>());
        System.Windows.Clipboard.SetText(text);
    }

    private void ShowValidation(string message)
    {
        ValidationText.Text = message;
        ValidationText.Visibility = Visibility.Visible;
    }

    private void HideValidation() => ValidationText.Visibility = Visibility.Collapsed;

    private void ShowPassword_Checked(object sender, RoutedEventArgs e)
    {
        _syncingPassword = true;
        VisiblePasswordInput.Text = PasswordInput.Password;
        _syncingPassword = false;
        PasswordInput.Visibility = Visibility.Collapsed;
        VisiblePasswordInput.Visibility = Visibility.Visible;
        VisiblePasswordInput.Focus();
        VisiblePasswordInput.CaretIndex = VisiblePasswordInput.Text.Length;
    }

    private void ShowPassword_Unchecked(object sender, RoutedEventArgs e)
    {
        _syncingPassword = true;
        PasswordInput.Password = VisiblePasswordInput.Text;
        _syncingPassword = false;
        VisiblePasswordInput.Visibility = Visibility.Collapsed;
        PasswordInput.Visibility = Visibility.Visible;
        PasswordInput.Focus();
    }

    private void PasswordInput_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (_syncingPassword)
        {
            return;
        }
        _syncingPassword = true;
        VisiblePasswordInput.Text = PasswordInput.Password;
        _syncingPassword = false;
    }

    private void VisiblePasswordInput_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (_syncingPassword)
        {
            return;
        }
        _syncingPassword = true;
        PasswordInput.Password = VisiblePasswordInput.Text;
        _syncingPassword = false;
    }

    private void OpenDirectoryButton_Click(object sender, RoutedEventArgs e)
    {
        var startInfo = new ProcessStartInfo("explorer.exe") { UseShellExecute = true };
        startInfo.ArgumentList.Add(_paths.BaseDirectory);
        Process.Start(startInfo);
    }

    private void Window_StateChanged(object? sender, EventArgs e)
    {
        if (_windowLoaded && WindowState == WindowState.Minimized)
        {
            Hide();
        }
    }

    private void ShowFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private void RequestExit()
    {
        _exitRequested = true;
        Close();
    }

    private async void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (_allowClose)
        {
            return;
        }
        e.Cancel = true;
        if (!_exitRequested)
        {
            Hide();
            return;
        }
        if (_closing)
        {
            return;
        }
        _closing = true;
        IsEnabled = false;
        Hide();
        _trayIcon.Visible = false;
        try
        {
            await _coreService.DisposeAsync();
        }
        catch (Exception ex)
        {
            AddLog($"关闭核心时发生错误：{ex.Message}");
        }
        finally
        {
            _trayIcon.Dispose();
            _allowClose = true;
            System.Windows.Application.Current.Shutdown();
        }
    }
}
