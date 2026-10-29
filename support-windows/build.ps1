param([string]$Python = 'python')
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
& $Python -m PyInstaller --noconfirm --onefile --console `
    --name RemoteConsentAgent-unsigned --version-file version.txt `
    --hidden-import win32timezone --hidden-import servicemanager `
    --hidden-import win32serviceutil --collect-binaries win32 main.py
if ($LASTEXITCODE -ne 0) { throw 'Windows component build failed' }
} finally {
    Pop-Location
}
