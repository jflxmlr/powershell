<#
    .SYNOPSIS
        Author: James Miller
        Date: 07-31-2024
        Summary: Script to force tentacle updates.
    .DESCRIPTION
        Script to force tentacle updates.
        Based on script by Octopus.
    .PARAMETER OctopusDeployUrl
        Octopus Deploy Url.
    .PARAMETER OctopusDeployApiKey
        Octopus Deploy Api Key.
    .PARAMETER Environment
        Deployment Target/tentacle environment.
        Only accepts:
        PROD, DEV, QA, STAGE, DEVOPS, or ALL
    .EXAMPLE
        .\Start-TentacleUpgrade.ps1 -Environment PROD -OctopusDeployUrl OctopusDeployUrl -OctopusDeployApiKey "OctopusDeployApiKey"
    .NOTES
        Original Script:
        https://octopus.com/docs/octopus-rest-api/examples/deployment-targets/upgrade-machines
#>
param (
    [Parameter()][string]$OctopusDeployUrl,
    [Parameter()][string]$OctopusDeployApiKey,
    [Parameter()][ValidateSet("PROD","DEV","QA","STAGE","DEVOPS","ALL")][string]$Environment = "ALL"
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
$spaces = $repository.Spaces.GetAll()
try {
    $spaces | Where-Object {$_.Name -eq "Default"} | ForEach-Object {
    #$spaces | ForEach-Object {
        $space = $_
        $repositoryForSpace = $client.ForSpace($space)
        $MachineEnvironment = $repositoryForSpace.Environments.FindByName($Environment)
        $machines = $repositoryForSpace.Machines.GetAll() | Where-Object {($_.EnvironmentIds -contains $MachineEnvironment.Id)} | Where-Object {$_.IsDisabled -ne "True"}

        # Create new task resource
        $task = New-Object Octopus.Client.Model.TaskResource
        $task.Name = "Upgrade"
        $task.Description = "Upgrade machines"
        $task.Arguments.Add("MachineIds", $machines.Id)

        # Execute
        $repositoryForSpace.Tasks.Create($task)
    }
}
catch {
    Write-Host $_.Exception.Message
}