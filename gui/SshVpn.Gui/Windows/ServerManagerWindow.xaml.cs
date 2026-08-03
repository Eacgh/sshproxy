using System.Windows;
using SshVpn.Gui.Models;
using SshVpn.Gui.Services;

namespace SshVpn.Gui.Windows;

// 服务器列表管理窗口：增删改服务器条目。
// 通过事件把修改结果通知主窗口刷新下拉框。
internal partial class ServerManagerWindow : Window
{
    private readonly ServerProfileService _service;
    private List<ServerProfile> _profiles;

    public event Action? ProfilesChanged;

    public ServerManagerWindow(ServerProfileService service, List<ServerProfile> profiles)
    {
        InitializeComponent();
        _service = service;
        _profiles = profiles;
        RefreshList();
    }

    private void RefreshList()
    {
        ServerList.ItemsSource = null;
        ServerList.ItemsSource = _profiles;
        ServerList.SelectedIndex = _profiles.Count > 0 ? 0 : -1;
    }

    private async void AddButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new ServerEditWindow(new ServerProfile { Name = "新服务器", ProxyPort = 1080 });
        if (dialog.ShowDialog() == true)
        {
            _profiles.Add(dialog.Profile);
            await SaveAndRefreshAsync();
        }
    }

    private async void EditButton_Click(object sender, RoutedEventArgs e)
    {
        if (ServerList.SelectedItem is not ServerProfile selected)
        {
            return;
        }
        var dialog = new ServerEditWindow(selected);
        if (dialog.ShowDialog() == true)
        {
            await SaveAndRefreshAsync();
        }
    }

    private async void DeleteButton_Click(object sender, RoutedEventArgs e)
    {
        if (ServerList.SelectedItem is not ServerProfile selected)
        {
            return;
        }
        if (System.Windows.MessageBox.Show(this, $"确定删除服务器“{selected.Name}”吗？", "删除服务器",
                System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Question) != System.Windows.MessageBoxResult.Yes)
        {
            return;
        }
        _profiles.Remove(selected);
        await SaveAndRefreshAsync();
    }

    private async Task SaveAndRefreshAsync()
    {
        try
        {
            await _service.SaveAsync(_profiles);
            RefreshList();
            ProfilesChanged?.Invoke();
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(this, ex.Message, "保存失败", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
        }
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();
}
