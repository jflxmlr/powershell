<#
    .SYNOPSIS
        Author: James Miller
        Date: 04-16-2024
        Summary: Script to list unused Octopus projects.
    .DESCRIPTION
        Script to list unused Octopus projects based on release creation and date parameters.
        Based on script by Octopus.
    .PARAMETER JSON
        Full file path for JSON import document.
    .EXAMPLE
        .\New-OctopusTenant.ps1 -Environment PROD -CustomerType Metering -JSON "C:\JM\code\Sentryx\_setup\JSON\muellertestga.json"
    .NOTES
        Original Script:
        https://octopus.com/docs/octopus-rest-api/examples/projects/find-unused-projects
#>
param (
    [Parameter()][string]$OctopusDeployUrl,
    [Parameter()][string]$OctopusDeployApiKey,
    [Parameter()][string]$DaysSinceLastRelease = 90
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
$CSV = "$ScriptDirectory\$ODName-UnusedProjects.csv"
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
# Declare Octopus variables
$endpoint = New-Object Octopus.Client.OctopusServerEndpoint $OctopusDeployUrl, $OctopusDeployApiKey
$repository = New-Object Octopus.Client.OctopusRepository $endpoint
$client = New-Object Octopus.Client.OctopusClient $endpoint
$currentUtcTime = $(Get-Date).ToUniversalTime()
$oldProjects = @()
$Disabled = @()
$NoRelease = @()

# Loop through spaces
Write-Host "Processing projects, this may take some time..."
foreach ($space in $repository.Spaces.GetAll()) {
    # Get space
    $space = $repository.Spaces.FindByName($space.Name)
    $repositoryForSpace = $client.ForSpace($space)

    # Get all projects in space
    $projects = $repositoryForSpace.Projects.GetAll()

    # Loop through projects
    foreach ($project in $projects) {
        # Create project object
        $probject = [PSCustomObject]@{
            Name = $project.Name
            Status = $null
            Id = $project.id
            Space = $space.Name
            Enabled = $true
            ReleaseCount = $null
            LastReleaseDays = $null
            Comment = $null
        }
        # Get number of releases
        $releases = $repositoryForSpace.Projects.GetReleases($project)
        $probject.ReleaseCount = $releases.Items.Count
        # Check the length of time
        If ($releases.Items.Count -gt 0) {
            $assembledDate = [datetime]::Parse($releases.Items[0].Assembled)
            $assembledDate = $assembledDate.ToUniversalTime()
            $dateDiff = $currentUtcTime - $assembledDate
            $probject.LastReleaseDays = [math]::Round($dateDiff.TotalDays)
        } else {
            $probject.LastReleaseDays = 0
        }
        # Check for disabled
        if ($project.IsDisabled) {
            $probject.Status = "DISABLED"
            $probject.Enabled = $false
            $probject.Comment = "$($project.Name) is disabled."
            $Disabled += $probject
            continue
        }
        # Get project releases
        if ($releases.Items.Count -eq 0) {
            $probject.Status = "NO-RELEASE"
            $probject.Comment = "No releases found for $($project.Name)"
            $NoRelease += $probject
            continue
        }
        # Get current projects
        if ($dateDiff.TotalDays -le $daysSinceLastRelease) {
            $probject.Status = "CURRENT"
            $probject.Comment = "Active project - last release was $($dateDiff.TotalDays) days ago."
            $NoRelease += $probject
            continue
        }
        # Add to oldProjects if past daysSinceLastRelease
        if ($dateDiff.TotalDays -gt $daysSinceLastRelease) {
            $probject.Status = "OLD-PROJECT"
            $probject.Comment = "Last release was $($dateDiff.TotalDays) days ago."
            $oldProjects += $probject
        }
        Remove-Variable -Name "probject" -Force
    }
}

Write-Host "Compiling CSV of Projects that meet criteria..."
$Results = @()
$Disabled | Foreach-Object {$Results += $_}
$NoRelease | Foreach-Object {$Results += $_}
$oldProjects | Foreach-Object {$Results += $_}
$Results | ConvertTo-Csv | Out-file -FilePath $CSV -encoding ASCII
Write-Host "Actions complete."
Write-Host "CSV Output: $CSV"
# End