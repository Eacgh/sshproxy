; SSH VPN 安装包配置
; 编译：ISCC.exe packaging\sshvpn-setup.iss
; 产物：artifacts\SSHVPN-Setup-win-x64.exe

#define MyAppName "SSH VPN"
#define MyAppVersion "0.2.1"
#define MyAppExeName "SshVpn.exe"
#define MyAppPublisher "Eacgh"

[Setup]
AppId={{8A3F2C1E-9D4B-4E6F-9A2C-7B5D3E1F8A40}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\SSH VPN
DefaultGroupName=SSH VPN
; 便携设计：程序目录必须可写（配置、核心、日志都写在 EXE 同目录）
; 因此默认安装到用户目录而非 Program Files
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=..\artifacts
OutputBaseFilename=SSHVPN-Setup-win-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; 自包含发布，安装包内已含运行时
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务:"; Flags: unchecked
Name: "startmenuicon"; Description: "创建开始菜单快捷方式"; GroupDescription: "附加任务:"

[Files]
Source: "..\artifacts\sshvpn-full-sc\SshVpn.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\artifacts\sshvpn-full-sc\sshvpn-core.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\artifacts\sshvpn-full-sc\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: startmenuicon
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "立即运行 SSH VPN"; Flags: nowait postinstall skipifsilent
