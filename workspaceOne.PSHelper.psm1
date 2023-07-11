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
    $workSpaceOne.apiKey = $apiKey
    $workSpaceOne.orgId = $orgId
    $tempArray = $workSpaceOne.apiCredential.ToCharArray() | % {[byte] $_}
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($tempArray, `
        $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    New-Item -Path $workSpaceOne.registryURL -Force | Out-null
    New-ItemProperty -Path $workSpaceOne.registryURL -Name serverURL -Value $serverURL | Out-Null
    New-ItemProperty -Path $workSpaceOne.registryURL -Name apiCredential -Value $encrypted | Out-Null
    New-ItemProperty -Path $workSpaceOne.registryURL -Name apiKey -Value $apiKey | Out-Null
    New-ItemProperty -Path $workSpaceOne.registryURL -Name orgId -Value $orgId | Out-Null
    write-host "Connected to $($workSpaceOne.serverURL)`n"
}

Function Get-WS1ApiCrediential {
    # Contruct REST HEADER
    $restHeader = @{
        "Authorization"  = "Basic $($workSpaceOne.apiCredential)";
        "aw-tenant-code" = $workSpaceOne.apiKey;
        "Accept" = "application/json";
        "Content-Type"   = "application/json;version=2";
    }
    $restHeader
}

# Returns Workspace ONE UEM Console Version
Function Get-WS1ConsoleVersion {
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $endpointURL = $workSpaceOne.serverURL + "/system/info"
    $header = Get-WS1ApiCrediential
    $response = Invoke-RestMethod -Method Get -Uri $endpointURL -Headers $header 
    #$response.ProductVersion
    $response
}

# Returns devices under management
Function Get-WS1Device {
    param(
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)][string]$deviceID
    )
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if ($deviceID) {
        $endpointURL = $workSpaceOne.serverURL + "/mdm/devices/" + $deviceId
    } else {
        $endpointURL = $workSpaceOne.serverURL + "/mdm/devices/search"
    }
    $header = Get-WS1ApiCrediential
    $response = Invoke-RestMethod -Method Get -Uri $endpointURL -Headers $header
    if ($deviceID) {
        $response
    } else {
        $response.devices
    }
}

# Returns Organization Group by Name
Function Get-WS1OrgGroup {
    param(
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)][string]$orgGroupName
    )
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if ($orgGroupName) {
        $endpointURL = $workSpaceOne.serverURL + "/system/groups/search/?groupid=" + $workspaceONEOrgGroupName
    } else {
    $endpointURL = $workSpaceOne.serverURL + "/system/groups/search"
    }
    $header = Get-WS1ApiCrediential
    $response = Invoke-RestMethod -Method Get -Uri $endpointURL -Headers $header
    $response.LocationGroups
}

Function Get-WS1Tag {
    param(
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)][string]$tagName
    )
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $orgId = (Get-WS1OrgGroup -orgGroupName $workSpaceOne.orgId).Id.Value
    if ($tagName) {
        $endpointURL = $workSpaceOne.serverURL + "/mdm/tags/search/?name=" + $tagName + "&organizationgroupid=" + $orgId
    } else {
        $endpointURL = $workSpaceOne.serverURL + "/mdm/tags/search/?organizationgroupid=" + $orgId
    }
    $header = Get-WS1ApiCrediential    
    $response = Invoke-RestMethod -Method Get -Uri $endpointURL -Headers $header
    $response.tags
}

Function Get-WS1TaggedDevice {
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$tagId
    )
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $endpointURL = $workSpaceOne.serverURL + "/mdm/tags/" + $tagId + "/devices"
    $header = Get-WS1ApiCrediential    
    $response = Invoke-RestMethod -Method Get -Uri $endpointURL -Headers $header
    $response.device
}

Function New-WS1Tag {
param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$tagName
    )
    $orgId = (Get-WS1OrgGroup -orgGroupName $workSpaceOne.orgId).Id.Value
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $endpointURL = $workSpaceOne.serverURL + "/mdm/tags/addtag"
    $body = @()
    $body = [pscustomobject]@{
        'TagName' = $tagName;
        'TagAvatar' = $tagName;
        'TagType' = 1;
        'LocationGroupId' = $orgId
    }
    $json = $body | ConvertTo-Json
    $header = Get-WS1ApiCrediential    
    $response = Invoke-RestMethod -Method Post -Uri $endpointURL -Headers $header -Body $json
    $response
}

Function Add-WS1DeviceTag {
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$deviceId,
        [Parameter(Mandatory=$true)][string]$tagId
    )
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $endpointURL = $workSpaceOne.serverURL + "/mdm/tags/" + $tagId + "/adddevices"
    $deviceToAdd = @()
    $deviceToAdd += $deviceId
    $values = @()
    $values = [pscustomobject]@{
        'Value' = $DeviceToAdd;
    }
    $body = [pscustomobject]@{
        'BulkValues' = $values;
    }
    $json = $body | ConvertTo-Json
    $header = Get-WS1ApiCrediential    
    $response = Invoke-RestMethod -Method Post -Uri $endpointURL -Headers $header -Body $json
    $response
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
    $workSpaceOne.apiKey = $registryKey.apiKey
    $workSpaceOne.orgId = $registryKey.orgId
    $encrypted = $registryKey.apiCredential
    $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, `
        $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    $decrypted | % { $apiBase64 += [char] $_} | Out-Null
    $workSpaceOne.apiCredential = $apiBase64
    write-host "Connected to $($workSpaceOne.serverURL)`n"
}
Write-host "Cmdlets added:`n$(Get-Command | where {$_.ModuleName -eq 'WorkSpaceOne.PSHelper'})`n"