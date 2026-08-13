using System.Net;
using System.Windows;
using SshVpn.Gui.Models;

namespace SshVpn.Gui.Windows;

// 单个服务器的编辑对话框，新增/编辑共用。
internal partial class ServerEditWindow : Window
{
    private readonly ServerProfile _original;

    public ServerProfile Profile { get; private set; }

    public ServerEditWindow(ServerProfile profile)
    {
        InitializeComponent();
        _original = profile;
        Profile = new ServerProfile
        {
            Name = profile.Name,
            ServerAddress = profile.ServerAddress,
            Username = profile.Username,
            Password = profile.Password,
            ProxyPort = profile.ProxyPort,
            DnsServer = profile.DnsServer
        };
        NameBox.Text = Profile.Name;
        ServerAddressBox.Text = Profile.ServerAddress;
        UsernameBox.Text = Profile.Username;
        PasswordInput.Password = Profile.Password;
        ProxyPortBox.Text = Profile.ProxyPort.ToString();
        DnsServerBox.Text = Profile.DnsServer ?? string.Empty;
    }

    private void OkButton_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(NameBox.Text))
        {
            System.Windows.MessageBox.Show(this, "请填写服务器名称", "提示", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
            return;
        }
        if (string.IsNullOrWhiteSpace(ServerAddressBox.Text))
        {
            System.Windows.MessageBox.Show(this, "请填写服务器地址", "提示", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
            return;
        }
        if (string.IsNullOrWhiteSpace(UsernameBox.Text))
        {
            System.Windows.MessageBox.Show(this, "请填写用户名", "提示", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
            return;
        }
        if (string.IsNullOrEmpty(PasswordInput.Password))
        {
            System.Windows.MessageBox.Show(this, "请填写密码", "提示", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
            return;
        }
        if (!int.TryParse(ProxyPortBox.Text, out var proxyPort) || proxyPort is < 1 or > 65535)
        {
            System.Windows.MessageBox.Show(this, "代理端口必须在 1 到 65535 之间", "提示", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
            return;
        }
        var dnsServer = DnsServerBox.Text.Trim();
        if (!IsValidDnsServer(dnsServer))
        {
            System.Windows.MessageBox.Show(this, "DNS 必须填写 IP 或 IP:端口；留空使用系统 DNS", "提示", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
            return;
        }

        Profile.Name = NameBox.Text.Trim();
        Profile.ServerAddress = ServerAddressBox.Text.Trim();
        Profile.Username = UsernameBox.Text.Trim();
        Profile.Password = PasswordInput.Password;
        Profile.ProxyPort = proxyPort;
        Profile.DnsServer = string.IsNullOrEmpty(dnsServer) ? null : dnsServer;

        // 把编辑结果写回原对象：列表持有 _profiles 中的原始对象引用，
        // 只更新副本会导致列表和主窗口表单都看不到修改。
        _original.Name = Profile.Name;
        _original.ServerAddress = Profile.ServerAddress;
        _original.Username = Profile.Username;
        _original.Password = Profile.Password;
        _original.ProxyPort = Profile.ProxyPort;
        _original.DnsServer = Profile.DnsServer;
        DialogResult = true;
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private static bool IsValidDnsServer(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || IPAddress.TryParse(value.Trim('[', ']'), out _))
        {
            return true;
        }
        return IPEndPoint.TryParse(value, out var endpoint) && endpoint.Port is >= 1 and <= 65535;
    }
}
