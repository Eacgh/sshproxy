using System.Threading;
using System.Windows;

namespace SshVpn.Gui;

public partial class App : System.Windows.Application
{
    // 命名互斥锁保证单实例：双开 GUI 会各拉起一个核心，争用 SOCKS5 端口和
    // Wintun 虚拟网卡。锁随进程结束由系统自动释放，异常退出不会留下死锁。
    private Mutex? _singleInstanceMutex;
    private bool _ownsMutex;

    protected override void OnStartup(StartupEventArgs e)
    {
        _singleInstanceMutex = new Mutex(true, @"Local\SshVpn.SingleInstance", out _ownsMutex);
        if (!_ownsMutex)
        {
            System.Windows.MessageBox.Show("SSH VPN 已经在运行，请使用系统托盘图标操作。", "SSH VPN",
                System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
            Shutdown();
            return;
        }
        DispatcherUnhandledException += App_DispatcherUnhandledException;
        base.OnStartup(e);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (_ownsMutex)
        {
            _singleInstanceMutex?.ReleaseMutex();
        }
        _singleInstanceMutex?.Dispose();
        base.OnExit(e);
    }

    // 兜底捕获 UI 线程上的未处理异常（如 async void 事件处理器中的写盘失败），
    // 避免整个应用直接闪退；具体操作错误仍由各按钮的 try/catch 负责提示。
    private void App_DispatcherUnhandledException(object sender,
        System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
    {
        System.Windows.MessageBox.Show($"发生未处理的错误：{e.Exception.Message}", "SSH VPN",
            System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
        e.Handled = true;
    }
}
