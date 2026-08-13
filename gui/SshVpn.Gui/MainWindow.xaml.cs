using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Media;
using SshVpn.Gui.Models;
using SshVpn.Gui.Services;
using SshVpn.Gui.Windows;
using DrawingSystemIcons = System.Drawing.SystemIcons;
using Forms = System.Windows.Forms;

namespace SshVpn.Gui;

public partial class MainWindow : Window
{
    private readonly PortablePaths _paths = new();
    private readonly ConfigService _configService;
    private readonly CorePayloadService _corePayloadService;
    private readonly CoreProcessService _coreService;
    private readonly ServerProfileService _serverService;
    private readonly Forms.NotifyIcon _trayIcon;
    private readonly Forms.ToolStripMenuItem _trayToggleItem;
    private List<ServerProfile> _profiles = new();
    private bool _syncingPassword;
    private bool _syncingServerSelection;
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
        _serverService = new ServerProfileService(_paths);
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

            await LoadProfilesAsync();
        }
        catch (Exception ex)
        {
            ShowValidation(ex.Message);
            AddLog(ex.Message);
        }
    }

    // LoadProfilesAsync 读取服务器列表；没有列表时用现有 config.json 生成默认条目（旧版兼容）。
    private async Task LoadProfilesAsync()
    {
        _profiles = await _serverService.LoadAsync();
        if (_profiles.Count == 0)
        {
            var config = await _configService.LoadAsync();
            if (!string.IsNullOrWhiteSpace(config.ServerAddress))
            {
                _profiles.Add(ServerProfileService.FromAppConfig(config));
                await _serverService.SaveAsync(_profiles);
                AddLog("已从现有配置生成默认服务器条目");
            }
        }

        _syncingServerSelection = true;
        ServerListBox.ItemsSource = null;
        ServerListBox.ItemsSource = _profiles;
        ServerListBox.SelectedIndex = _profiles.Count > 0 ? 0 : -1;
        _syncingServerSelection = false;

        if (_profiles.Count == 0)
        {
            // 没有任何服务器时，仍尝试读取 config.json 填充表单（保持旧行为）。
            var config = await _configService.LoadAsync();
            ServerAddressBox.Text = config.ServerAddress;
            UsernameBox.Text = config.Username;
            PasswordInput.Password = config.Password;
            ProxyPortBox.Text = config.ProxyPort.ToString();
            DnsServerBox.Text = config.DnsServer ?? string.Empty;
            UpdateEndpointText(config.ProxyPort);
            AddLog(File.Exists(_paths.ConfigPath) ? "已读取同目录配置" : "尚未创建配置文件");
        }
    }

    // ApplyProfileToForm 把选中服务器刷新到表单。
    private void ApplyProfileToForm(ServerProfile? profile)
    {
        if (profile == null)
        {
            return;
        }
        ServerAddressBox.Text = profile.ServerAddress;
        UsernameBox.Text = profile.Username;
        PasswordInput.Password = profile.Password;
        VisiblePasswordInput.Text = profile.Password;
        ProxyPortBox.Text = profile.ProxyPort.ToString();
        DnsServerBox.Text = profile.DnsServer ?? string.Empty;
        UpdateEndpointText(profile.ProxyPort);
    }

    private void ServerListBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (_syncingServerSelection || ServerListBox.SelectedItem is not ServerProfile profile)
        {
            return;
        }
        ApplyProfileToForm(profile);
        AddLog($"已切换到服务器：{profile.Name}");
    }

    private void ManageServersButton_Click(object sender, RoutedEventArgs e)
    {
        var selectedName = (ServerListBox.SelectedItem as ServerProfile)?.Name;
        var window = new ServerManagerWindow(_serverService, _profiles);
        window.ProfilesChanged += () =>
        {
            var previousIndex = ServerListBox.SelectedIndex;
            _syncingServerSelection = true;
            ServerListBox.ItemsSource = null;
            ServerListBox.ItemsSource = _profiles;
            // 尽量保持原来的选中项。
            ServerListBox.SelectedIndex = _profiles.Count > 0
                ? Math.Max(0, Math.Min(previousIndex, _profiles.Count - 1))
                : -1;
            _syncingServerSelection = false;
            if (ServerListBox.SelectedItem is ServerProfile current)
            {
                ApplyProfileToForm(current);
            }
        };
        window.Owner = this;
        window.ShowDialog();
    }

    private async void SaveButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            await SaveConfigAsync();
        }
        catch (Exception ex)
        {
            ShowValidation(ex.Message);
            AddLog(ex.Message);
        }
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
            var profileName = (ServerListBox.SelectedItem as ServerProfile)?.Name;
            await _coreService.StartAsync(GlobalModeCheckBox.IsChecked == true, profileName: profileName);
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

        // 只更新服务器列表 servers.json，不再单独生成 config.json；
        // 核心启动时通过 -profile 直接读取列表中的条目。
        if (ServerListBox.SelectedItem is ServerProfile current)
        {
            current.ServerAddress = config.ServerAddress;
            current.Username = config.Username;
            current.Password = config.Password;
            current.ProxyPort = config.ProxyPort;
            current.DnsServer = config.DnsServer;
        }
        else
        {
            // 列表为空：把表单内容保存为新条目，避免修改悄悄丢失，
            // 也保证连接时始终有 -profile 可用，不会因缺少 config.json 失败。
            _profiles.Add(ServerProfileService.FromAppConfig(config));
        }
        await _serverService.SaveAsync(_profiles);

        // 重新绑定列表以刷新显示（ServerProfile 未实现属性变更通知），
        // 并保持当前选中项；无选中时选中刚创建的最后一项。
        var selectedIndex = ServerListBox.SelectedIndex;
        _syncingServerSelection = true;
        ServerListBox.ItemsSource = null;
        ServerListBox.ItemsSource = _profiles;
        ServerListBox.SelectedIndex = selectedIndex >= 0 && selectedIndex < _profiles.Count
            ? selectedIndex
            : _profiles.Count > 0 ? _profiles.Count - 1 : -1;
        _syncingServerSelection = false;

        UpdateEndpointText(proxyPort);
        AddLog("配置已保存到服务器列表");
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
        TryUpdateTraffic(message);
        var line = $"{DateTime.Now:HH:mm:ss}  {FormatLogMessage(message)}";
        LogList.Items.Add(line);
        while (LogList.Items.Count > 1000)
        {
            LogList.Items.RemoveAt(0);
        }
        LogList.ScrollIntoView(LogList.Items[^1]);
    }

    // 解析核心每秒输出的“流量统计”日志，更新状态栏显示。
    // 格式：... 消息="流量统计" 上行=xx 下行=xx
    private static readonly Regex TrafficLogRegex = new(
        @"流量统计.*?上行=([0-9]+)\s+下行=([0-9]+)",
        RegexOptions.Compiled);

    private void TryUpdateTraffic(string message)
    {
        if (!message.Contains("流量统计", StringComparison.Ordinal))
        {
            return;
        }
        var match = TrafficLogRegex.Match(message);
        if (!match.Success)
        {
            return;
        }
        var upload = ulong.TryParse(match.Groups[1].Value, out var u) ? u : 0;
        var download = ulong.TryParse(match.Groups[2].Value, out var d) ? d : 0;
        TrafficText.Text = $"上行 {FormatBytes(upload)} · 下行 {FormatBytes(download)}";
    }

    private static string FormatBytes(ulong bytes)
    {
        const ulong kb = 1 << 10;
        const ulong mb = 1 << 20;
        const ulong gb = 1 << 30;
        return bytes switch
        {
            >= gb => $"{bytes / (double)gb:0.00} GB",
            >= mb => $"{bytes / (double)mb:0.00} MB",
            >= kb => $"{bytes / (double)kb:0.00} KB",
            _ => $"{bytes} B"
        };
    }

    private async void ResetTrafficButton_Click(object sender, RoutedEventArgs e)
    {
        if (System.Windows.MessageBox.Show(this, "确定清零累计流量统计吗？", "重置流量",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
        {
            return;
        }
        try
        {
            if (_coreService.State is CoreState.Starting or CoreState.Connected)
            {
                // 核心运行中：停止后用 -reset-traffic 重新启动，让核心清零并持久化。
                AddLog("正在重启核心以重置流量统计");
                await _coreService.StopAsync();
                var profileName = (ServerListBox.SelectedItem as ServerProfile)?.Name;
                await _coreService.StartAsync(GlobalModeCheckBox.IsChecked == true, resetTraffic: true, profileName: profileName);
                AddLog("已重置流量统计");
            }
            else
            {
                // 核心未运行：直接删除持久化文件。
                var trafficPath = Path.Combine(_paths.BaseDirectory, "traffic.json");
                if (File.Exists(trafficPath))
                {
                    File.Delete(trafficPath);
                }
                TrafficText.Text = "上行 0 B · 下行 0 B";
                AddLog("已重置流量统计");
            }
        }
        catch (Exception ex)
        {
            AddLog($"重置流量统计失败：{ex.Message}");
        }
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
