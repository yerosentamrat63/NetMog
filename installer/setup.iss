; =====================================================================
; NetMog Inno Setup Script
; Ships the NetMog executable only.
;
; The packet driver (Npcap) is NOT bundled: Npcap's free licence does not
; allow redistributing its installer, so setup detects it and points the
; user at npcap.com instead. NetMog works with Npcap installed in
; "WinPcap API-compatible Mode", or with WinPcap 4.1.3.
; =====================================================================

#define MyAppName "NetMog"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "NetMog Software"
#define MyAppURL "https://github.com/yerosentamrat63/NetMog"
#define MyAppExeName "NetMog.exe"
#define NpcapUrl "https://npcap.com/#download"

[Setup]
AppId={{E8F5A376-88B1-4A6D-981D-21D8A9F3C641}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputBaseFilename=NetMog_Setup_v{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Automatically start NetMog when Windows logs in"; GroupDescription: "Startup Options:"; Flags: unchecked

[Files]
; Published single-file executable (build with build-installer.ps1)
Source: "..\bin\publish\NetMog.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
; Auto-start on boot if requested
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#MyAppName}"; ValueData: """{app}\{#MyAppExeName}"""; Tasks: autostart; Flags: uninsdeletevalue

[Run]
; The driver is installed by the user, from Npcap's own signed installer.
Filename: "{#NpcapUrl}"; Description: "Open npcap.com to install the packet driver (required)"; Flags: shellexec postinstall nowait skipifsilent

; Launch application after setup completes
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
function HasPcapDriver(): Boolean;
var
  WinPcapDll, NpcapDll: String;
begin
  WinPcapDll := ExpandConstant('{sys}\wpcap.dll');
  NpcapDll := ExpandConstant('{sys}\Npcap\wpcap.dll');
  Result := FileExists(WinPcapDll) or FileExists(NpcapDll);
end;

procedure InitializeWizard();
begin
  if not HasPcapDriver() then
    MsgBox('NetMog needs the Npcap packet driver, which is not installed.' + #13#10#13#10 +
           'Download it from npcap.com and install it with' + #13#10 +
           '"Install Npcap in WinPcap API-compatible Mode" checked.' + #13#10#13#10 +
           'Setup will open that page for you at the end.',
           mbInformation, MB_OK);
end;
