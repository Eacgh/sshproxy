# Sign the Go core and optionally the published GUI with a local self-signed
# code-signing certificate. This machine's WDAC policy requires executables to
# meet the enterprise signing level; freshly built unsigned binaries are blocked.
# Usage: powershell -ExecutionPolicy Bypass -File scripts/sign-core.ps1
# Optional: -GuiPath <path to SshVpn.exe> to sign the published GUI as well.

param(
    [string]$CorePath = (Join-Path $PSScriptRoot "..\gui\SshVpn.Gui\Resources\sshvpn-core.exe"),
    [string]$GuiPath = ""
)

$ErrorActionPreference = "Stop"

$certName = "SSH VPN Local"

# Reuse an existing cert if present, otherwise create a fresh one.
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq ("CN=" + $certName) } | Select-Object -First 1

if (-not $cert) {
    Write-Host "Creating self-signed code-signing cert $certName ..."
    $cert = New-SelfSignedCertificate -Type CodeSigningCert `
        -Subject ("CN=" + $certName) `
        -CertStoreLocation Cert:\CurrentUser\My `
        -KeyAlgorithm RSA -KeyLength 2048 `
        -NotAfter (Get-Date).AddYears(3)
}

# The root must be in the trusted root store for the signature to verify.
$exportPath = Join-Path ([System.IO.Path]::GetTempPath()) "sshvpn-root.cer"
Export-Certificate -Cert $cert -FilePath $exportPath -Type CERT | Out-Null
Import-Certificate -FilePath $exportPath -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
Remove-Item $exportPath -Force -ErrorAction SilentlyContinue

function Sign-File([string]$Path) {
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path $fullPath)) {
        Write-Host "Skip missing file: $fullPath"
        return
    }
    $signature = Set-AuthenticodeSignature -FilePath $fullPath -Certificate $cert -HashAlgorithm SHA256
    if ($signature.Status -ne "Valid") {
        throw ("Signing failed {0}: {1}" -f $fullPath, $signature.StatusMessage)
    }
    Write-Host "Signed: $fullPath"
}

Sign-File $CorePath
if ($GuiPath) {
    Sign-File $GuiPath
}

# Remove any duplicate same-name certs left over from earlier runs.
Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq ("CN=" + $certName) -and $_.Thumbprint -ne $cert.Thumbprint } |
    ForEach-Object { Remove-Item $_.PSPath -Force -ErrorAction SilentlyContinue }
