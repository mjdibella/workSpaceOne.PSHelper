Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.Web
Add-Type -AssemblyName System
Add-Type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@

function Connect-WS1 {
    param(
        [Parameter(Mandatory=$true)][string]$serverURL,
        [Parameter(Mandatory=$true)][string]$apiUser,
        [Parameter(Mandatory=$true)][string]$apiKey,
        [Parameter(Mandatory=$true)][string]$orgId
    )
    $securedValue = Read-Host -prompt "Password" -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securedValue)
    $apiPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    $workSpaceOne.serverURL = $serverURL
    $workSpaceOne.apiCredential = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($apiUser + ":" + $apiPass))
    $workSpaceOne.apiKey = $registryKey.apiKey
    $workSpaceOne.orgId = $registryKey.orgId
    $tempArray = $workSpaceOne.apiCredential.ToCharArray() | % {[byte] $_}
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($tempArray, `
        $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    New-Item -Path $workSpaceOne.registryURL -Force | Out-null
    New-ItemProperty -Path $workSpaceOne.registryURL -Name serverURL -Value $serverURL | Out-Null
    New-ItemProperty -Path $workSpaceOne.registryURL -Name apiCredential -Value $encrypted | Out-Null
    New-ItemProperty -Path $workSpaceOne.registryURL -Name apiKey -Value $apiKey | Out-Null
    New-ItemProperty -Path $workSpaceOne.registryURL -Name orgId -Value $ordId | Out-Null
    write-host "Connected to $($workSpaceOne.serverURL)`n"
}

Function Get-WS1ApiCrediential {
    # Contruct REST HEADER
    $restHeader = @{
    "Authorization"  = "Basic $($workSpaceOne.apiCredential)";
    "aw-tenant-code" = $workSpaceOne.apiKey;}
    $restHeader
}

# Returns Workspace ONE UEM Console Version
Function Get-WS1ConsoleVersion {
    $endpointURL = $workSpaceOne.serverURL + "/system/info"
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $header = Get-WS1ApiCrediential
    $endpointURL
    $response = Invoke-RestMethod -Method Get -Uri $endpointURL -Headers $header
    $response.ProductVersion
}

$workSpaceOne = [ordered]@{
    registryURL = "HKCU:\Software\VMWare\WorkspaceOne.PSHelper"
    serverURL = "" # https://cnxxx.awmdm.com
    apiUser = "" # APIAdmin
    apiCredential = "" # SuperSecretPW01*
    apiKey = "" # your API Key
    orgId = "" # GroupIdName as used for device assignment
}
New-Variable -Name workSpaceOne -Value $workSpaceOne -Scope script -Force
$registryKey = (Get-ItemProperty -Path $workSpaceOne.registryURL -ErrorAction SilentlyContinue)
if ($registryKey -eq $null) {
    Write-Warning "Autoconnect failed.  API key not found in registry.  Use Connect-WS1 to connect manually."
} else {
    $workSpaceOne.serverURL = $registryKey.serverURL
    $workSpaceOne.apiCredential = $registryKey.apiCredential
    $workSpaceOne.apiKey = $registryKey.apiKey
    $workSpaceOne.orgId = $registryKey.orgId
    write-host "Connected to $($workSpaceOne.serverURL)`n"
}
Write-host "Cmdlets added:`n$(Get-Command | where {$_.ModuleName -eq 'WorkSpaceOne.PSHelper'})`n"