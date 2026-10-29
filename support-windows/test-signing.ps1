$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$source = (Resolve-Path dist/RemoteConsentAgent-unsigned.exe).Path
$testBuild = Join-Path $PSScriptRoot 'build/signing-test.exe'
$signtool = (Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe' |
    Sort-Object FullName -Descending | Select-Object -First 1).FullName
if (-not $signtool) { throw 'signtool unavailable' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Elevated isolated signing test required'
}
Copy-Item -LiteralPath $source -Destination $testBuild -Force
Write-Host 'Create ephemeral code-signing test certificate'
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=JumpStart Local Test Only' -CertStoreLocation Cert:\CurrentUser\My
# CurrentUser protected-root changes can require an interactive confirmation.
# Use the elevated disposable runner's machine store for this fixture only;
# remove exactly this certificate in finally. Production trust is unchanged.
$rootStore = [Security.Cryptography.X509Certificates.X509Store]::new('Root','LocalMachine')
$publisherStore = [Security.Cryptography.X509Certificates.X509Store]::new('TrustedPublisher','LocalMachine')
try {
    Write-Host 'Trust ephemeral certificate in the isolated test machine store'
    $rootStore.Open('ReadWrite'); $rootStore.Add($cert)
    $publisherStore.Open('ReadWrite'); $publisherStore.Add($cert)
    $signed = Set-AuthenticodeSignature -LiteralPath $testBuild -Certificate $cert -HashAlgorithm SHA256
    if ($signed.Status -ne 'Valid') { throw 'Test build signature is not trusted' }
    Write-Host 'Verify Authenticode with signtool'
    & $signtool verify /pa $testBuild
    if ($LASTEXITCODE) { throw 'signtool verify failed' }
    Write-Host 'Exercise publisher/version gates against the real signed binary'
    & .\.venv\Scripts\python.exe test_update.py $testBuild $source $cert.Thumbprint
    if ($LASTEXITCODE) { throw 'Updater signature/version tests failed' }
} finally {
    $rootStore.Remove($cert); $rootStore.Close()
    $publisherStore.Remove($cert); $publisherStore.Close()
    Remove-Item -LiteralPath ('Cert:\CurrentUser\My\' + $cert.Thumbprint) -DeleteKey
    Remove-Item -LiteralPath $testBuild -ErrorAction SilentlyContinue
}
