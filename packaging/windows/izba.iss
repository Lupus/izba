; izba Windows installer (Inno Setup).
; Build:
;   iscc /DMyAppVersion=<ver> /DStageDir=<abs path to stage> packaging\windows\izba.iss
; Expected stage layout:
;   <StageDir>\bin\izba.exe
;   <StageDir>\bin\izba-jail-helper.exe
;   <StageDir>\bin\izba-app.exe          (GUI; optional component)
;   <StageDir>\bin\libexec\openvmm.exe
;   <StageDir>\bin\libexec\mkfs.erofs.exe
;   <StageDir>\artifacts\vmlinux
;   <StageDir>\artifacts\vmlinux-usb
;   <StageDir>\artifacts\initramfs.cpio.gz

#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif
#ifndef StageDir
  #error StageDir must be defined (/DStageDir=...)
#endif

[Setup]
AppId={{B5E8F3A2-7C4D-4E1A-9B2F-1B2C3D4E5F60}
AppName=izba
AppVersion={#MyAppVersion}
AppPublisher=Konstantin Olkhovskiy
DefaultDirName={autopf}\izba
DefaultGroupName=izba
DisableProgramGroupPage=yes
OutputDir=dist
OutputBaseFilename=izba-setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
ChangesEnvironment=yes
; Backstop only: PrepareToInstall below quiesces izba gracefully (sandboxes,
; daemon, leftovers). Restart Manager cannot close console processes like
; `izba daemon run` / openvmm.exe, so anything it still finds is terminated
; rather than surfacing "unable to automatically close all applications".
CloseApplications=force
RestartApplications=no

[Components]
Name: "cli"; Description: "izba CLI + microVM runtime"; Types: full custom; Flags: fixed
Name: "gui"; Description: "izba desktop app (GUI)";     Types: full

[Files]
Source: "{#StageDir}\bin\izba.exe";             DestDir: "{app}\bin";         Flags: ignoreversion;                 Components: cli
Source: "{#StageDir}\bin\izba-jail-helper.exe"; DestDir: "{app}\bin";         Flags: ignoreversion;                 Components: cli
Source: "{#StageDir}\bin\libexec\*";     DestDir: "{app}\bin\libexec"; Flags: ignoreversion recursesubdirs;  Components: cli
Source: "{#StageDir}\artifacts\*";       DestDir: "{app}\artifacts";   Flags: ignoreversion recursesubdirs;  Components: cli
Source: "{#StageDir}\bin\izba-app.exe";  DestDir: "{app}\bin";         Flags: ignoreversion;                 Components: gui
; Shutdown helper: extracted to {tmp} for PrepareToInstall, and installed so
; the uninstaller can quiesce izba before removing files.
Source: "stop-izba.ps1"; Flags: dontcopy
Source: "stop-izba.ps1"; DestDir: "{app}"; Flags: ignoreversion; Components: cli

[Icons]
Name: "{group}\izba"; Filename: "{app}\bin\izba-app.exe"; Components: gui

[Registry]
; Append {app}\bin to the system PATH (only if not already present).
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
    ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}\bin"; \
    Check: NeedsAddPath(ExpandConstant('{app}\bin'))

[Code]
// Quiesce izba so file replacement never hits in-use binaries: gracefully
// stop all sandboxes (`izba stop --all`) and the daemon (`izba daemon stop`),
// then force-kill anything still running from the install dir. All
// best-effort with timeouts inside the script; CloseApplications=force above
// is the final backstop.
procedure RunStopIzba(const ScriptPath: string);
var
  ResultCode: Integer;
begin
  Exec('powershell.exe',
    '-NoProfile -ExecutionPolicy Bypass -File "' + ScriptPath + '"' +
    ' -InstallDir "' + ExpandConstant('{app}') + '"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  ExtractTemporaryFile('stop-izba.ps1');
  RunStopIzba(ExpandConstant('{tmp}\stop-izba.ps1'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  // Right before file removal — the installed copy still exists here.
  if CurUninstallStep = usUninstall then
    RunStopIzba(ExpandConstant('{app}\stop-izba.ps1'));
end;

function NeedsAddPath(Param: string): Boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKLM,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Lowercase(Param) + ';', ';' + Lowercase(OrigPath) + ';') = 0;
end;
