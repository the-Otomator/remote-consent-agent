param(
    [Parameter(Mandatory=$true)][string]$File,
    [Parameter(Mandatory=$true)][string]$Thumbprint,
    [string]$SignTool
)
$ErrorActionPreference = 'Stop'
if (-not $SignTool) {
    $SignTool = (Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe' |
        Sort-Object FullName -Descending | Select-Object -First 1).FullName
}
if (-not $SignTool -or -not (Test-Path -LiteralPath $SignTool)) { throw 'signtool is required' }
# The standard Windows certificate store can hold a cloud-provider or smart-card
# key. No PFX/password/provider credential is accepted by this script or logged.
& $SignTool sign /sha1 $Thumbprint /fd SHA256 /tr https://timestamp.digicert.com /td SHA256 $File
if ($LASTEXITCODE -ne 0) { throw 'Authenticode signing failed' }
& $SignTool verify /pa /v $File
if ($LASTEXITCODE -ne 0) { throw 'Authenticode verification failed' }
