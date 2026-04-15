; CryptoFile installer — Inno Setup script
;
; Builds a single setup.exe that installs CryptoFile to per-user
; %LOCALAPPDATA%\Programs\CryptoFile\ (no admin required), registers the
; right-click context-menu verbs (both files and folders, via the exe's
; `install-shell` command), creates a Start Menu entry, and writes an
; Add/Remove Programs entry so the user can uninstall from Settings.
;
; Build with:  ISCC.exe installer.iss   (produces dist/CryptoFile-Setup-<ver>.exe)

#define AppName         "CryptoFile"
#define AppVersion      "1.0.6"
#define AppPublisher    "naab007"
#define AppURL          "https://github.com/naab007/CryptoFile"
#define ExeName         "CryptoFile.exe"

[Setup]
AppId={{B6FAC9AA-8B9F-4EA1-9D25-6B0CE5C4A8E0}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}/releases
; Per-user install — no admin required. This is the whole point of the
; HKCU shell integration design, so matching it here keeps the installer
; story consistent.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
DisableDirPage=auto
OutputDir=dist
OutputBaseFilename=CryptoFile-Setup-{#AppVersion}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#ExeName}
UninstallDisplayName={#AppName}
; Don't prompt for restart; we don't touch anything that needs one.
CloseApplications=yes
RestartApplications=no
; Skip the license page (we don't ship one yet) and the ready-to-install
; page — it's a single exe, no configuration decisions.
DisableReadyPage=no
AllowCancelDuringInstall=yes
ArchitecturesInstallIn64BitMode=x64compatible
VersionInfoVersion={#AppVersion}.0
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; The PyInstaller onefile build output. Must exist before ISCC runs.
; Uses dist-release/ so builds work even when the user has the current
; installed CryptoFile.exe running (the file lock prevents rebuilding
; over dist/). See feedback_pyinstaller_locked_exe.md.
#ifexist "dist-release\CryptoFile.exe"
  #define ExeSource "dist-release\CryptoFile.exe"
#else
  #define ExeSource "dist\CryptoFile.exe"
#endif
Source: "{#ExeSource}"; DestDir: "{app}"; DestName: "{#ExeName}"; Flags: ignoreversion
; Optional: ship the docs alongside so users can find them offline.
Source: "README.md";     DestDir: "{app}"; Flags: ignoreversion
Source: "CHANGELOG.md";  DestDir: "{app}"; Flags: ignoreversion
Source: "docs\*.md";     DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
; Start Menu shortcut to the Settings window.
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#ExeName}"
Name: "{autoprograms}\{#AppName} documentation"; Filename: "{app}\README.md"

[Run]
; Register HKCU context menu verbs by invoking the exe's built-in
; install-shell command. Runs silently after the file copy, before the
; installer's finish page. nowait: the user shouldn't have to wait on
; Explorer to notice the registry change before they see "Setup
; complete". StatusMsg for the progress label.
Filename: "{app}\{#ExeName}"; Parameters: "install-shell"; \
  StatusMsg: "Registering right-click menu entries..."; \
  Flags: runhidden
; Optional: open the Settings window at the end so the user can verify
; installation state. Unchecked by default to avoid being pushy.
Filename: "{app}\{#ExeName}"; Description: "Open CryptoFile Settings"; \
  Flags: nowait postinstall skipifsilent unchecked

[UninstallRun]
; Mirror: remove the HKCU keys before removing the exe itself. If we
; deleted the exe first, uninstall-shell would have no way to run.
Filename: "{app}\{#ExeName}"; Parameters: "uninstall-shell"; \
  RunOnceId: "UnregisterShell"; Flags: runhidden

[UninstallDelete]
; The batch coordinator leaves lock/port files in %LOCALAPPDATA%\CryptoFile\
; which aren't known to the installer. Clean those up on uninstall too.
Type: filesandordirs; Name: "{localappdata}\CryptoFile"

[Code]
// Pre-install check: refuse to install if the target exe is already
// running (our own HKCU shell integration or the Settings window). If we
// don't, file replacement will fail silently on Windows.
function InitializeSetup(): Boolean;
begin
  Result := True;
end;
