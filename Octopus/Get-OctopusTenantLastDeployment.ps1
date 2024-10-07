<#
    .SYNOPSIS
        Title: Get-OctopusTenantLastDeployment
        Authors: James Miller
        Date: 04/30/2024
    .DESCRIPTION
        Script to collect Octopus tenants and last deployment date.
    .NOTES
        
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
$CSV = "$ScriptDirectory\$ODName-tenant-info.csv"
# Create new Log/Output file each time
If (!(Test-Path $CSV)) {
    New-Item -Path $CSV -ItemType File -Force | Out-Null
} else {
    Remove-Item -Path $CSV -Force | Out-Null
    New-Item -Path $CSV -ItemType File -Force | Out-Null
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

# Octopus variables
$endpoint = New-Object Octopus.Client.OctopusServerEndpoint $OctopusDeployUrl, $OctopusDeployApiKey
$repository = New-Object Octopus.Client.OctopusRepository $endpoint
# Get Tenants
Write-Host "Getting all tenants..."
$Tenants = $repository.Tenants.FindAll()
#$Tenants = $repository.Tenants.FindByName("akron")
# Get Deployments
Write-Host "Collecting Deployments..."
$projects = @()
$environments = @()
$script:deployments = New-Object System.Collections.Generic.List[System.Object]
$repository.Deployments.Paginate($projects, $environments, {
    param ($page)
    Write-Host "Found $($page.Items.Count) deployments.";
    $deployments.AddRange($page.Items);
    return $True;
})
# Create Export List
Write-Host "Populating Export List..."
$currentUtcTime = $(Get-Date).ToUniversalTime()
$ExportList = @()
$Tenants | ForEach-Object {
    $tenant = $_
    # Create tenant object
    $tenobject = [PSCustomObject]@{
        Name = $tenant.Name
        Status = $null
        Id = $tenant.id
        LastDeployment = $null
        LastDeployDays = $null
        LastDeployYears = $null
        Comment = $null
    }
    Write-Host "Getting Last Deployment for $($tenobject.Name)"
    $SiteDeps = $Deployments | Where-Object {$_.TenantId -eq $tenobject.Id} | Select-Object Id,Name,Created,DeployedBy,EnvironmentId,TenantId,TaskId,ProjectId,SpaceId
    $LastDepTime = $SiteDeps.Created.DateTime | Sort-Object -Descending | Select-Object -First 1
    # Get project releases
    if (($SiteDeps.Items.Count -le 0) -and ([string]::IsNullOrWhiteSpace($SiteDeps))) {
        $tenobject.LastDeployDays = "0"
        $tenobject.LastDeployment = "NEVER"
        $tenobject.Status = "NO-DEPLOYS"
        $tenobject.LastDeployYears = "0"
        $tenobject.Comment = "No deployments found for $($tenobject.Name)"
    } else {
        # Check the length of time
        $tenobject.LastDeployment = $LastDepTime
        $dateDiff = $currentUtcTime - $LastDepTime
        $tenobject.LastDeployDays = $dateDiff.Days
        # Determine last release in days, years
        $1year = 365
        if ($dateDiff.Days -gt $1year) {
            $years = [math]::Round($dateDiff.Days / $1year)
            $tenobject.LastDeployYears = $years
            $tenobject.Status = "OLD-TENANT"
            $tenobject.Comment = "Last deployment was $($dateDiff.TotalDays) days (~ $years years) ago."
        } else {
            $tenobject.Status = "CURRENT"
            $tenobject.LastDeployYears = "0"
            $tenobject.Comment = "Last deployment was $($dateDiff.TotalDays) days ago."
        }
    }
    $ExportList += $tenobject
    Remove-Variable -Name "tenobject" -Force
}
# Export
Write-Host "Exporting to: $CSV"
$ExportList | ConvertTo-Csv | Set-Content -Path $CSV