param(
    [Parameter(Mandatory)][string]$File,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$Thumbprint,
    [Parameter(Mandatory)][string]$SignTool
)
$ErrorActionPreference = 'Stop'
$target = (Resolve-Path -LiteralPath $File).Path
if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $ExpectedSha256) { throw 'CI artifact hash mismatch' }
# Authenticate in SimplySign Desktop using the phone before running this script.
# The cloud key remains in the provider HSM. Never export it or put codes here.
& $SignTool sign /sha1 $Thumbprint /fd SHA256 /tr https://time.certum.pl /td SHA256 $target
if ($LASTEXITCODE -ne 0) { throw 'Signing failed' }
& $SignTool verify /pa /all $target
if ($LASTEXITCODE -ne 0) { throw 'Authenticode verification failed' }
$signature = Get-AuthenticodeSignature -LiteralPath $target
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $Thumbprint) { throw 'Publisher mismatch' }
Get-FileHash -LiteralPath $target -Algorithm SHA256
