; SSH VPN 安装包配置（纯 Go 单文件版）
; 编译：ISCC.exe packaging\sshvpn-setup.iss
; 产物：artifacts\SSHVPN-Setup-win-x64.exe

#define MyAppName "SSH VPN"
#define MyAppVersion "0.3.0"
#define MyAppExeName "SshVpn.exe"
#define MyAppPublisher "Eacgh"

[Setup]
AppId={{8A3F2C1E-9D4B-4E6F-9A2C-7B5D3E1F8A40}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\SSH VPN
DefaultGroupName=SSH VPN
; 便携设计：程序目录必须可写（配置、日志、状态与 WebView2 数据都写在 EXE 同目录）
; 因此默认安装到用户目录而非 Program Files
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=..\artifacts
OutputBaseFilename=SSHVPN-Setup-win-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务:"; Flags: unchecked
Name: "startmenuicon"; Description: "创建开始菜单快捷方式"; GroupDescription: "附加任务:"

[Files]
; wintun.dll 已内嵌于 SshVpn.exe，首次启用 Wintun 模式时自动释放到同目录
Source: "..\artifacts\sshvpn-portable\SshVpn.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: startmenuicon
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppName}"; Description: "立即运行 SSH VPN"; Flags: nowait postinstall skipifsilent
