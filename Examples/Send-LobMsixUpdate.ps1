<#
    .SYNOPSIS
        This script is an example for updating an existing MSIX LOB application in Intune.

    .Parameter User
        Specifies the UPN you will use to authenticate to the Intune Service.

    .Parameter ModulePath
        Specifies the path on your local machine to the MSIX-LobIntune module .psm1 file.

    .Parameter MSIXPath
        Specifies the path on your local machine to the .msix file that you wish to upload as an
        LOB application.

    .Parameter DisplayName
        Specifies the Display Name of the LOB application in Intune that you wish to update.

    .Notes
        This script leverages the MSIX-LOBIntune module in this repo.

        Use of the MSIX-LOBIntune module requires the AzureAD PowerShell module.

        The user that you authenticate to Intune as must have the appropriate permissions to perform the
        application upload tasks.
#>

# Parameters
[cmdletbinding()]
param
(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $User,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $ModulePath,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $MSIXPath,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $DisplayName
)

# Import the requisite module.
Import-Module -Name $ModulePath

# Authenticate user to Intune.
$global:authToken = Get-AuthToken -User $User

# Upload MSIX application to Intune.
Set-MsixLobUpdate -SourceFile $MSIXPath -DisplayName $DisplayName
