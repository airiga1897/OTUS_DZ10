# Dot-source this file to populate only the current PowerShell session.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if ($MyInvocation.InvocationName -ne '.') { throw 'Используйте: . ./scripts/env.ps1' }
$env:YC_CLOUD_ID = Read-Host 'ID облака YC'
$env:YC_FOLDER_ID = Read-Host 'ID каталога YC'
$iamSecret = Read-Host 'IAM-токен YC (yc iam create-token)' -AsSecureString
try {
    $iamPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($iamSecret)
    $env:YC_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($iamPointer)
} finally {
    if ($iamPointer) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($iamPointer) }
    $iamSecret.Dispose()
    Remove-Variable iamSecret,iamPointer -ErrorAction SilentlyContinue
}
Write-Host 'Реквизиты заданы только в окружении текущей сессии.'
