<#
    .SYNOPSIS
        Title: Get-OctopusUsageCounts
        Authors: Bob Walker & Mark Harrison
        Date: 02/20/2023?
    .DESCRIPTION
        Script to collect Octopus usage count information.
    .NOTES
        From GitHub:
        https://github.com/OctopusDeploy/OctopusDeploy-Api/blob/master/REST/PowerShell/Administration/GetUsageCounts.ps1
        
        Cleaned-up and improved by James Miller, 04/02/2024
        Changed these variables into params:
        $OctopusDeployUrl = "https://yourinstance"
        $OctopusDeployApiKey = "API-XXXX"
#>
param (
    [Parameter()][string]$OctopusDeployUrl,
    [Parameter()][string]$OctopusDeployApiKey
)
# Param handling
If (([string]::IsNullOrWhiteSpace($OctopusDeployUrl)) -or ([string]::IsNullOrWhiteSpace($OctopusDeployApiKey))) {
    If ([string]::IsNullOrWhiteSpace($OctopusDeployUrl)) {
        Write-Host "Cannot continue - Octopus Deploy URL not defined!" -ForegroundColor Red
        Write-Host "Please try again with OctopusDeployUrl parameter value..." -ForegroundColor Red
    }
    If ([string]::IsNullOrWhiteSpace($OctopusDeployApiKey)) {
        Write-Host "Cannot continue - Octopus Deploy API Key not defined!" -ForegroundColor Red
        Write-Host "Please try again with OctopusDeployApiKey parameter value..." -ForegroundColor Red
    }
    return $false
}
# Initialization & Variables
$script:ScriptInvocation = (Get-Variable MyInvocation -Scope Script).Value
$script:ScriptPath = $ScriptInvocation.MyCommand.Path           # Full script path & name
$script:ScriptDirectory = Split-Path $ScriptPath                # Script folder/path
$script:ScriptName = $ScriptInvocation.MyCommand.Name           # Script file name
#$script:InvocationPath = $ScriptInvocation.InvocationName       # .\$ScriptName
$ODName = ($OctopusDeployUrl -split "/")[2]
$Log = "$ScriptDirectory\$ODName-counts.txt"
# Create new Log/Output file each time
If (!(Test-Path $log)) {
    New-Item -Path $log -ItemType File -Force | Out-Null
} else {
    Remove-Item -Path $log -Force | Out-Null
    New-Item -Path $log -ItemType File -Force | Out-Null
}
# Configure Octopus API/Octopus.Client.dll, Server, API Key
$OctoCheck = Get-Package Octopus.Client -ErrorAction SilentlyContinue
If ([string]::IsNullOrWhiteSpace($OctoCheck)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-Package Octopus.Client -source https://www.nuget.org/api/v2 -SkipDependencies
}
$OctoClient = (Get-Item ((Get-Package Octopus.Client -ErrorAction SilentlyContinue).source)).Directory.FullName
$OctoSubFolder = (Get-ChildItem -Path "$OctoClient/lib" | Where-Object {$_.Name -ne "netstandard2.0"}).Name
$Octopath = "$OctoClient/lib/$OctoSubFolder/Octopus.Client.dll"
If (Test-Path $Octopath) {Add-Type -Path $Octopath} else {
    Write-Host "Cannot load Octopus.Client.dll!" -ForegroundColor Red
    Read-Host "Press ENTER to exit..."
    Exit
}

## To avoid nuking your instance, this script will pull back 50 items at a time and count them.  It is designed to run on instances as far back as 3.4.

# Functions
function Get-OctopusUrl {
    param (
        $EndPoint,
        $SpaceId,
        $OctopusUrl
    )
    $octopusUrlToUse = $OctopusUrl
    if ($OctopusUrl.EndsWith("/")) {
        $octopusUrlToUse = $OctopusUrl.Substring(0, $OctopusUrl.Length - 1)
    }
    if ($EndPoint -match "/api") {
        if (!$EndPoint.StartsWith("/api")) {
            $EndPoint = $EndPoint.Substring($EndPoint.IndexOf("/api"))
        }
        return "$octopusUrlToUse$EndPoint"
    }
    if ([string]::IsNullOrWhiteSpace($SpaceId)) {
        return "$octopusUrlToUse/api/$EndPoint"
    }
    return "$octopusUrlToUse/api/$spaceId/$EndPoint"
}
function Invoke-OctopusApi {
    param (
        $endPoint,
        $spaceId,
        $octopusUrl,
        $apiKey
    )
    try {
        $url = Get-OctopusUrl -EndPoint $endPoint -SpaceId $spaceId -OctopusUrl $octopusUrl
        Write-Host "Invoking $url"
        return Invoke-RestMethod -Method Get -Uri $url -Headers @{"X-Octopus-ApiKey" = "$apiKey" } -ContentType 'application/json; charset=utf-8' -TimeoutSec 60        
    } catch {
        Write-Host "There was an error making a Get call to the $url.  Please check that for more information." -ForegroundColor Red
        if ($null -ne $_.Exception.Response) {
            if ($_.Exception.Response.StatusCode -eq 401) {
                Write-Host "Unauthorized error returned from $url, please verify API key and try again" -ForegroundColor Red
            }
            elseif ($_.ErrorDetails.Message) {
                Write-Host -Message "Error calling $url StatusCode: $($_.Exception.Response) $($_.ErrorDetails.Message)" -ForegroundColor Red
                Write-Host $_.Exception -ForegroundColor Red
            } else {
                Write-Host $_.Exception -ForegroundColor Red
            }
        } else {
            Write-Host $_.Exception -ForegroundColor Red
        }
        Write-Host "Stopping the script from proceeding" -ForegroundColor Red
        exit 1
    }
}
function Get-OctopusObjectCount {
    param (
        $endPoint,
        $spaceId,
        $octopusUrl,
        $apiKey
    )
    $itemCount = 0
    $currentPage = 1
    $pageSize = 50
    $skipValue = 0
    $haveReachedEndOfList = $false
    while ($haveReachedEndOfList -eq $false) {
        $currentEndPoint = "$($endPoint)?skip=$skipValue&take=$pageSize"
        $itemList = Invoke-OctopusApi -endPoint $currentEndPoint -spaceId $spaceId -octopusUrl $octopusUrl -apiKey $apiKey
        foreach ($item in $itemList.Items) {
            if ($null -ne (Get-Member -InputObject $item -Name "IsDisabled" -MemberType Properties)) {
                if ($item.IsDisabled -eq $false) {
                    $itemCount += 1
                }
            } else {
                $itemCount += 1    
            }
        }
        if ($currentPage -lt $itemList.NumberOfPages) {
            $skipValue = $currentPage * $pageSize
            $currentPage += 1
            Write-Host "The endpoint $endpoint has reported there are $($itemList.NumberOfPages) pages.  Setting the skip value to $skipValue and re-querying"
        } else {
            $haveReachedEndOfList = $true    
        }
    }
    return $itemCount
}
function Get-OctopusDeploymentTargetsCount {
    param (
        $spaceId,
        $octopusUrl,
        $apiKey
    )
    $targetCount = @{
        TargetCount = 0 
        ActiveTargetCount = 0
        UnavailableTargetCount = 0        
        DisabledTargets = 0
        ActiveListeningTentacleTargets = 0
        ActivePollingTentacleTargets = 0
        ActiveSshTargets = 0        
        ActiveKubernetesCount = 0
        ActiveAzureWebAppCount = 0
        ActiveAzureServiceFabricCount = 0
        ActiveAzureCloudServiceCount = 0
        ActiveOfflineDropCount = 0    
        ActiveECSClusterCount = 0
        ActiveCloudRegions = 0  
        ActiveFtpTargets = 0
        DisabledListeningTentacleTargets = 0
        DisabledPollingTentacleTargets = 0
        DisabledSshTargets = 0        
        DisabledKubernetesCount = 0
        DisabledAzureWebAppCount = 0
        DisabledAzureServiceFabricCount = 0
        DisabledAzureCloudServiceCount = 0
        DisabledOfflineDropCount = 0    
        DisabledECSClusterCount = 0
        DisabledCloudRegions = 0  
        DisabledFtpTargets = 0            
    }
    $currentPage = 1
    $pageSize = 50
    $skipValue = 0
    $haveReachedEndOfList = $false
    while ($haveReachedEndOfList -eq $false) {
        $currentEndPoint = "machines?skip=$skipValue&take=$pageSize"
        $itemList = Invoke-OctopusApi -endPoint $currentEndPoint -spaceId $spaceId -octopusUrl $octopusUrl -apiKey $apiKey
        foreach ($item in $itemList.Items) {
            $targetCount.TargetCount += 1
            if ($item.IsDisabled -eq $true) {
                $targetCount.DisabledTargets += 1
                if ($item.EndPoint.CommunicationStyle -eq "None") {
                    $targetCount.DisabledCloudRegions += 1
                } 
                elseif ($item.EndPoint.CommunicationStyle -eq "TentacleActive") {
                    $targetCount.DisabledPollingTentacleTargets += 1
                }
                elseif ($item.EndPoint.CommunicationStyle -eq "TentaclePassive") {
                    $targetCount.DisabledListeningTentacleTargets += 1
                }
                # Cover newer k8s agent and traditional worker-API approach
                elseif ($item.EndPoint.CommunicationStyle -ilike "Kubernetes*") {
                    $targetCount.DisabledKubernetesCount += 1
                }
                elseif ($item.EndPoint.CommunicationStyle -eq "AzureWebApp") {
                    $targetCount.DisabledAzureWebAppCount += 1
                }
                elseif ($item.EndPoint.CommunicationStyle -eq "Ssh") {
                    $targetCount.DisabledSshTargets += 1
                }
                elseif ($item.EndPoint.CommunicationStyle -eq "Ftp") {
                    $targetCount.DisabledFtpTargets += 1
                }
                elseif ($item.EndPoint.CommunicationStyle -eq "AzureCloudService") {
                    $targetCount.DisabledAzureCloudServiceCount += 1
                }
                elseif ($item.EndPoint.CommunicationStyle -eq "AzureServiceFabricCluster") {
                    $targetCount.DisabledAzureServiceFabricCount += 1
                }
                elseif ($item.EndPoint.CommunicationStyle -eq "OfflineDrop") {
                    $targetCount.DisabledOfflineDropCount += 1
                }
                else {
                    $targetCount.DisabledECSClusterCount += 1
                }
            } else {
                if ($item.HealthStatus -eq "Healthy" -or $item.HealthStatus -eq "HealthyWithWarnings") {
                    $targetCount.ActiveTargetCount += 1
                } else {
                    $targetCount.UnavailableTargetCount += 1    
                }
                if ($item.EndPoint.CommunicationStyle -eq "None") {
                    $targetCount.ActiveCloudRegions += 1
                }
                elseif ($item.EndPoint.CommunicationStyle -eq "TentacleActive") {
                    $targetCount.ActivePollingTentacleTargets += 1
                }
                elseif ($item.EndPoint.CommunicationStyle -eq "TentaclePassive") {
                    $targetCount.ActiveListeningTentacleTargets += 1
                }
                # Cover newer k8s agent and traditional worker-API approach
                elseif ($item.EndPoint.CommunicationStyle -ilike "Kubernetes*") {
                    $targetCount.ActiveKubernetesCount += 1
                }
                elseif ($item.EndPoint.CommunicationStyle -eq "AzureWebApp") {
                    $targetCount.ActiveAzureWebAppCount += 1
                }
                elseif ($item.EndPoint.CommunicationStyle -eq "Ssh") {
                    $targetCount.ActiveSshTargets += 1
                }
                elseif ($item.EndPoint.CommunicationStyle -eq "Ftp") {
                    $targetCount.ActiveFtpTargets += 1
                }
                elseif ($item.EndPoint.CommunicationStyle -eq "AzureCloudService") {
                    $targetCount.ActiveAzureCloudServiceCount += 1
                }
                elseif ($item.EndPoint.CommunicationStyle -eq "AzureServiceFabricCluster") {
                    $targetCount.ActiveAzureServiceFabricCount += 1
                }
                elseif ($item.EndPoint.CommunicationStyle -eq "OfflineDrop") {
                    $targetCount.ActiveOfflineDropCount += 1
                }
                else {
                    $targetCount.ActiveECSClusterCount += 1
                }
            }                                
        }

        if ($currentPage -lt $itemList.NumberOfPages) {
            $skipValue = $currentPage * $pageSize
            $currentPage += 1
            Write-Host "The endpoint $endpoint has reported there are $($itemList.NumberOfPages) pages.  Setting the skip value to $skipValue and re-querying"
        } else {
            $haveReachedEndOfList = $true    
        }
    }
    return $targetCount
}
# Create zeroed object
$ObjectCounts = @{
    ProjectCount = 0
    TenantCount = 0
    TargetCount = 0
    DisabledTargets = 0
    ActiveTargetCount = 0
    UnavailableTargetCount = 0
    ActiveListeningTentacleTargets = 0
    ActivePollingTentacleTargets = 0
    ActiveSshTargets = 0
    ActiveKubernetesCount = 0
    ActiveAzureWebAppCount = 0
    ActiveAzureServiceFabricCount = 0
    ActiveAzureCloudServiceCount = 0
    ActiveOfflineDropCount = 0
    ActiveECSClusterCount = 0
    ActiveCloudRegions = 0
    ActiveFtpTargets = 0
    DisabledListeningTentacleTargets = 0
    DisabledPollingTentacleTargets = 0
    DisabledSshTargets = 0
    DisabledKubernetesCount = 0
    DisabledAzureWebAppCount = 0
    DisabledAzureServiceFabricCount = 0
    DisabledAzureCloudServiceCount = 0
    DisabledOfflineDropCount = 0
    DisabledECSClusterCount = 0
    DisabledCloudRegions = 0
    DisabledFtpTargets = 0
    WorkerCount = 0
    ListeningTentacleWorkers = 0
    PollingTentacleWorkers = 0
    SshWorkers = 0
    ActiveWorkerCount = 0
    UnavailableWorkerCount = 0
    WindowsLinuxMachineCount = 0
    LicensedTargetCount = 0
    LicensedWorkerCount = 0
}
# Collect Version Info
Write-Host "Getting Octopus Deploy Version Information"
$apiInformation = Invoke-OctopusApi -endPoint "/api" -spaceId $null -octopusUrl $OctopusDeployUrl -apiKey $OctopusDeployApiKey
$splitVersion = $apiInformation.Version -split "\."
$OctopusMajorVersion = [int]$splitVersion[0]
$OctopusMinorVersion = [int]$splitVersion[1]
$hasLicenseSummary = $OctopusMajorVersion -ge 4
$hasSpaces = $OctopusMajorVersion -ge 2019
$hasWorkers = ($OctopusMajorVersion -eq 2018 -and $OctopusMinorVersion -ge 7) -or $OctopusMajorVersion -ge 2019
$spaceIdList = @()
if ($hasSpaces -eq $true) {
    $OctopusSpaceList = Invoke-OctopusApi -endPoint "spaces?skip=0&take=10000" -octopusUrl $OctopusDeployUrl -spaceId $null -apiKey $OctopusDeployApiKey
    foreach ($space in $OctopusSpaceList.Items) {
        $spaceIdList += $space.Id
    }
} else {
    $spaceIdList += $null    
}
if ($hasLicenseSummary -eq $true) {
    Write-Host "Checking the license summary for this instance"
    $licenseSummary = Invoke-OctopusApi -endPoint "licenses/licenses-current-status" -octopusUrl $OctopusDeployUrl -spaceId $null -apiKey $OctopusDeployApiKey
    if ($null -ne (Get-Member -InputObject $licenseSummary -Name "NumberOfMachines" -MemberType Properties)) {
        $ObjectCounts.LicensedTargetCount = $licenseSummary.NumberOfMachines
    } else {
        foreach ($limit in $licenseSummary.Limits) {
            if ($limit.Name -eq "Targets") {
                Write-Host "Your instance is currently using $($limit.CurrentUsage) Targets"
                $ObjectCounts.LicensedTargetCount = $limit.CurrentUsage
            }
            if ($limit.Name -eq "Workers") {
                Write-Host "Your instance is currently using $($limit.CurrentUsage) Workers"
                $ObjectCounts.LicensedWorkerCount = $limit.CurrentUsage
            }
        }
    }
}
# Collect info for each Space ID
foreach ($spaceId in $spaceIdList) {
    Write-Host "Getting project counts for $spaceId"
    $activeProjectCount = Get-OctopusObjectCount -endPoint "projects" -spaceId $spaceId -octopusUrl $OctopusDeployUrl -apiKey $OctopusDeployApiKey
    Write-Host "$spaceId has $activeProjectCount active projects."
    $ObjectCounts.ProjectCount += $activeProjectCount
    Write-Host "Getting tenant counts for $spaceId"
    $activeTenantCount = Get-OctopusObjectCount -endPoint "tenants" -spaceId $spaceId -octopusUrl $OctopusDeployUrl -apiKey $OctopusDeployApiKey
    Write-Host "$spaceId has $activeTenantCount tenants."
    $ObjectCounts.TenantCount += $activeTenantCount
    Write-Host "Getting Infrastructure Summary for $spaceId"
    $infrastructureSummary = Get-OctopusDeploymentTargetsCount -spaceId $spaceId -octopusUrl $OctopusDeployUrl -apiKey $OctopusDeployApiKey
    Write-host "$spaceId has $($infrastructureSummary.TargetCount) targets"
    $ObjectCounts.TargetCount += $infrastructureSummary.TargetCount
    Write-Host "$spaceId has $($infrastructureSummary.ActiveTargetCount) Healthy Targets"
    $ObjectCounts.ActiveTargetCount += $infrastructureSummary.ActiveTargetCount
    Write-Host "$spaceId has $($infrastructureSummary.DisabledTargets) Disabled Targets"
    $ObjectCounts.DisabledTargets += $infrastructureSummary.DisabledTargets
    Write-Host "$spaceId has $($infrastructureSummary.UnavailableTargetCount) Unhealthy Targets"
    $ObjectCounts.UnavailableTargetCount += $infrastructureSummary.UnavailableTargetCount    
    Write-host "$spaceId has $($infrastructureSummary.ActiveListeningTentacleTargets) Active Listening Tentacles Targets"
    $ObjectCounts.ActiveListeningTentacleTargets += $infrastructureSummary.ActiveListeningTentacleTargets
    Write-host "$spaceId has $($infrastructureSummary.ActivePollingTentacleTargets) Active Polling Tentacles Targets"
    $ObjectCounts.ActivePollingTentacleTargets += $infrastructureSummary.ActivePollingTentacleTargets
    Write-host "$spaceId has $($infrastructureSummary.ActiveCloudRegions) Active Cloud Region Targets"
    $ObjectCounts.ActiveCloudRegions += $infrastructureSummary.ActiveCloudRegions
    Write-host "$spaceId has $($infrastructureSummary.ActiveOfflineDropCount) Active Offline Packages"
    $ObjectCounts.ActiveOfflineDropCount += $infrastructureSummary.ActiveOfflineDropCount
    Write-host "$spaceId has $($infrastructureSummary.ActiveSshTargets) Active SSH Targets"
    $ObjectCounts.ActiveSshTargets += $infrastructureSummary.ActiveSshTargets
    Write-host "$spaceId has $($infrastructureSummary.ActiveSshTargets) Active Kubernetes Targets"
    $ObjectCounts.ActiveKubernetesCount += $infrastructureSummary.ActiveKubernetesCount
    Write-host "$spaceId has $($infrastructureSummary.ActiveAzureWebAppCount) Active Azure Web App Targets"
    $ObjectCounts.ActiveAzureWebAppCount += $infrastructureSummary.ActiveAzureWebAppCount
    Write-host "$spaceId has $($infrastructureSummary.ActiveAzureServiceFabricCount) Active Azure Service Fabric Cluster Targets"
    $ObjectCounts.ActiveAzureServiceFabricCount += $infrastructureSummary.ActiveAzureServiceFabricCount
    Write-host "$spaceId has $($infrastructureSummary.ActiveAzureCloudServiceCount) Active (Legacy) Azure Cloud Service Targets"
    $ObjectCounts.ActiveAzureCloudServiceCount += $infrastructureSummary.ActiveAzureCloudServiceCount
    Write-host "$spaceId has $($infrastructureSummary.ActiveECSClusterCount) Active ECS Cluster Targets"
    $ObjectCounts.ActiveECSClusterCount += $infrastructureSummary.ActiveECSClusterCount
    Write-host "$spaceId has $($infrastructureSummary.ActiveFtpTargets) Active FTP Targets"
    $ObjectCounts.ActiveFtpTargets += $infrastructureSummary.ActiveFtpTargets
    Write-host "$spaceId has $($infrastructureSummary.DisabledListeningTentacleTargets) Disabled Listening Tentacles Targets"
    $ObjectCounts.DisabledListeningTentacleTargets += $infrastructureSummary.DisabledListeningTentacleTargets
    Write-host "$spaceId has $($infrastructureSummary.DisabledPollingTentacleTargets) Disabled Polling Tentacles Targets"
    $ObjectCounts.DisabledPollingTentacleTargets += $infrastructureSummary.DisabledPollingTentacleTargets
    Write-host "$spaceId has $($infrastructureSummary.DisabledCloudRegions) Disabled Cloud Region Targets"
    $ObjectCounts.DisabledCloudRegions += $infrastructureSummary.DisabledCloudRegions
    Write-host "$spaceId has $($infrastructureSummary.DisabledOfflineDropCount) Disabled Offline Packages"
    $ObjectCounts.DisabledOfflineDropCount += $infrastructureSummary.DisabledOfflineDropCount
    Write-host "$spaceId has $($infrastructureSummary.DisabledSshTargets) Disabled SSH Targets"
    $ObjectCounts.DisabledSshTargets += $infrastructureSummary.DisabledSshTargets
    Write-host "$spaceId has $($infrastructureSummary.ActiveSshTargets) Disabled Kubernetes Targets"
    $ObjectCounts.DisabledKubernetesCount += $infrastructureSummary.DisabledKubernetesCount
    Write-host "$spaceId has $($infrastructureSummary.DisabledAzureWebAppCount) Disabled Azure Web App Targets"
    $ObjectCounts.DisabledAzureWebAppCount += $infrastructureSummary.DisabledAzureWebAppCount
    Write-host "$spaceId has $($infrastructureSummary.DisabledAzureServiceFabricCount) Disabled Azure Service Fabric Cluster Targets"
    $ObjectCounts.DisabledAzureServiceFabricCount += $infrastructureSummary.DisabledAzureServiceFabricCount
    Write-host "$spaceId has $($infrastructureSummary.DisabledAzureCloudServiceCount) Disabled (Legacy) Azure Cloud Service Targets"
    $ObjectCounts.DisabledAzureCloudServiceCount += $infrastructureSummary.DisabledAzureCloudServiceCount
    Write-host "$spaceId has $($infrastructureSummary.DisabledECSClusterCount) Disabled ECS Cluster Targets"
    $ObjectCounts.DisabledECSClusterCount += $infrastructureSummary.DisabledECSClusterCount
    Write-host "$spaceId has $($infrastructureSummary.DisabledFtpTargets) Disabled FTP Targets"
    $ObjectCounts.DisabledFtpTargets += $infrastructureSummary.DisabledFtpTargets
    if ($hasWorkers -eq $true) {
        Write-Host "Getting worker information for $spaceId"
        $workerPoolSummary = Invoke-OctopusApi -endPoint "workerpools/summary" -spaceId $spaceId -octopusUrl $OctopusDeployUrl -apiKey $OctopusDeployApiKey 
        Write-host "$spaceId has $($workerPoolSummary.TotalMachines) Workers"
        $ObjectCounts.WorkerCount += $workerPoolSummary.TotalMachines
        Write-Host "$spaceId has $($workerPoolSummary.MachineHealthStatusSummaries.Healthy) Healthy Workers"
        $ObjectCounts.ActiveWorkerCount += $workerPoolSummary.MachineHealthStatusSummaries.Healthy
        Write-Host "$spaceId has $($workerPoolSummary.MachineHealthStatusSummaries.HasWarnings) Healthy with Warning Workers"
        $ObjectCounts.ActiveWorkerCount += $workerPoolSummary.MachineHealthStatusSummaries.HasWarnings
        Write-Host "$spaceId has $($workerPoolSummary.MachineHealthStatusSummaries.Unhealthy) Unhealthy Workers"
        $ObjectCounts.UnavailableWorkerCount += $workerPoolSummary.MachineHealthStatusSummaries.Unhealthy
        Write-Host "$spaceId has $($workerPoolSummary.MachineHealthStatusSummaries.Unknown) Workers with a Status of Unknown"
        $ObjectCounts.UnavailableWorkerCount += $workerPoolSummary.MachineHealthStatusSummaries.Unknown
        Write-host "$spaceId has $($workerPoolSummary.MachineEndpointSummaries.TentaclePassive) Listening Tentacles Workers"
        $ObjectCounts.ListeningTentacleWorkers += $workerPoolSummary.MachineEndpointSummaries.TentaclePassive
        Write-host "$spaceId has $($workerPoolSummary.MachineEndpointSummaries.TentacleActive) Polling Tentacles Workers"
        $ObjectCounts.PollingTentacleWorkers += $workerPoolSummary.MachineEndpointSummaries.TentacleActive        
        if ($null -ne (Get-Member -InputObject $workerPoolSummary.MachineEndpointSummaries -Name "Ssh" -MemberType Properties)) {
            Write-host "$spaceId has $($workerPoolSummary.MachineEndpointSummaries.TentacleActive) SSH Targets Workers"
            $ObjectCounts.SshWorkers += $workerPoolSummary.MachineEndpointSummaries.Ssh
        }
    }
}
# Deployment Target counts
# " INFO TEXT HERE..." | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
Write-Host "Calculating Windows and Linux Machine Count"
$ObjectCounts.WindowsLinuxMachineCount = $ObjectCounts.ActivePollingTentacleTargets + $ObjectCounts.ActiveListeningTentacleTargets + $ObjectCounts.ActiveSshTargets
if ($hasLicenseSummary -eq $false) {
    $ObjectCounts.LicensedTargetCount = $ObjectCounts.TargetCount - $ObjectCounts.ActiveCloudRegions - $ObjectCounts.DisabledTargets    
}
# Get node information
$nodeInfo = Invoke-OctopusApi -endPoint "octopusservernodes" -octopusUrl $OctopusDeployUrl -spaceId $null -apiKey $OctopusDeployApiKey
"The item counts are as follows:" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"    Instance ID: $($apiInformation.InstallationId)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"    Server Version: $($apiInformation.Version)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"    Number of Server Nodes: $($nodeInfo.TotalResults)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"    Licensed Target Count: $($ObjectCounts.LicensedTargetCount) (these are active targets de-duped across the instance if running a modern version of Octopus)" | Foreach-Object {Write-Host "$_" -ForegroundColor Green;"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"    Project Count: $($ObjectCounts.ProjectCount)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"    Tenant Count: $($ObjectCounts.TenantCount)"  | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"    Machine Counts (Active Linux and Windows Tentacles and SSH Connections): $($ObjectCounts.WindowsLinuxMachineCount)"  | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"    Deployment Target Count: $($ObjectCounts.TargetCount)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"        Active and Available Targets: $($ObjectCounts.ActiveTargetCount)" | Foreach-Object {Write-Host "$_" -ForegroundColor Green;"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"        Active but Unavailable Targets: $($ObjectCounts.UnavailableTargetCount)" | Foreach-Object {Write-Host "$_" -ForegroundColor Yellow;"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"        Active Target Breakdown" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            Listening Tentacle Target Count: $($ObjectCounts.ActiveListeningTentacleTargets)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            Polling Tentacle Target Count: $($ObjectCounts.ActivePollingTentacleTargets)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            SSH Target Count: $($ObjectCounts.ActiveSshTargets)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            Kubernetes Target Count: $($ObjectCounts.ActiveKubernetesCount)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            Azure Web App Target Count: $($ObjectCounts.ActiveAzureWebAppCount)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            Azure Service Fabric Cluster Target Count: $($ObjectCounts.ActiveAzureServiceFabricCount)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            Azure (Legacy) Cloud Service Target Count: $($ObjectCounts.ActiveAzureCloudServiceCount)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            AWS ECS Cluster Target Count: $($ObjectCounts.ActiveECSClusterCount)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            Offline Target Count: $($ObjectCounts.ActiveOfflineDropCount)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            Cloud Region Target Count: $($ObjectCounts.ActiveCloudRegions)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            Ftp Target Count: $($ObjectCounts.ActiveFtpTargets)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"        Disabled Targets Targets: $($ObjectCounts.DisabledTargets)" | Foreach-Object {Write-Host "$_" -ForegroundColor Red;"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"        Disabled Target Breakdown" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            Listening Tentacle Target Count: $($ObjectCounts.DisabledListeningTentacleTargets)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            Polling Tentacle Target Count: $($ObjectCounts.DisabledPollingTentacleTargets)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            SSH Target Count: $($ObjectCounts.DisabledSshTargets)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            Kubernetes Target Count: $($ObjectCounts.DisabledKubernetesCount)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            Azure Web App Target Count: $($ObjectCounts.DisabledAzureWebAppCount)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            Azure Service Fabric Cluster Target Count: $($ObjectCounts.DisabledAzureServiceFabricCount)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            Azure (Legacy) Cloud Service Target Count: $($ObjectCounts.DisabledAzureCloudServiceCount)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            AWS ECS Cluster Target Count: $($ObjectCounts.DisabledECSClusterCount)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            Offline Target Count: $($ObjectCounts.DisabledOfflineDropCount)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            Cloud Region Target Count: $($ObjectCounts.DisabledCloudRegions)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            Ftp Target Count: $($ObjectCounts.DisabledFtpTargets)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"    Worker Count: $($ObjectCounts.WorkerCount)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"        Active Workers: $($ObjectCounts.ActiveWorkerCount)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"        Unavailable Workers: $($ObjectCounts.UnavailableWorkerCount)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"        Worker Breakdown" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            Listening Tentacle Target Count: $($ObjectCounts.ListeningTentacleWorkers)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            Polling Tentacle Target Count: $($ObjectCounts.PollingTentacleWorkers)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}
"            SSH Target Count: $($ObjectCounts.SshWorkers)" | Foreach-Object {Write-Host "$_";"$_" | Out-file -FilePath $Log -append -encoding ASCII}

Write-Host "Results saved in: $Log"