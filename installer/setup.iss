; =====================================================================
; NetMog installer (Inno Setup 6)
;
; Ships the published NetMog.exe only. Build it with build-installer.ps1,
; which passes the version from NetMog.csproj in as MyAppVersion.
;
; The packet driver (Npcap) is NOT bundled: Npcap's free licence does not
; allow redistributing its installer, so setup detects it and points the
; user at npcap.com instead. NetMog works with Npcap installed in
; "WinPcap API-compatible Mode", or with WinPcap 4.1.3.
; =====================================================================

#ifndef MyAppVersion
  #define MyAppVersion "1.0.0"
#endif
#ifndef MyAppVersionQuad
  #define MyAppVersionQuad "1.0.0.0"
#endif

#define MyAppName "NetMog"
#define MyAppPublisher "NetMog Software"
#define MyAppURL "https://github.com/yerosentamrat63/NetMog"
#define MyAppExeName "NetMog.exe"
#define NpcapUrl "https://npcap.com/#download"

[Setup]
AppId={{E8F5A376-88B1-4A6D-981D-21D8A9F3C641}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
VersionInfoVersion={#MyAppVersionQuad}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=NetMog setup
VersionInfoProductName={#MyAppName}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
InfoBeforeFile=notice.txt
OutputDir=..\dist
OutputBaseFilename=NetMog_Setup_v{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
CloseApplications=yes
MinVersion=10.0.17763
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Published single-file executable (build with build-installer.ps1)
Source: "..\bin\publish\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Only offered when the driver is actually missing — the installer cannot
; ship it, so the user installs it from Npcap's own signed installer.
Filename: "{#NpcapUrl}"; Description: "Open npcap.com to install the packet driver (required)"; Flags: shellexec runasoriginaluser postinstall nowait skipifsilent; Check: not HasPcapDriver

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
