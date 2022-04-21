<#
    .Synopsis
        This script serves as an example of converting an existing installer to msix. This example uses the 7-zip msi
        installer.

        In this example, the latest version of the application is automatically downloaded
        via the winget utility.

        In order to run this script, the following tools are required:
            Msix Packaging Tool
            Windows 10 SDK
            Winget Utility
            The Msix-Automation module contained in this repo.

    .Parameter Certificate
        Specifies the path on your local machine to the certificate that will be used to sign
        the .msix file.

    .Parameter InstallerPath
        Specifies the path to the installation media for the Army Alert Tool.

    .Parameter ModulePath
        Specifies the path on your local machine to the MSIX-Automation module .psm1 file.

    .Parameter CertPasswordRequired
        Specifies whether a password is required for the specified .pfx certificate. Specify this parameter
        when a password is required for the .pfx.

    .Examples

        Example usage when a certificate password is required:
        ConvertTo-MSIXExampleProvideInstaller.ps1 -InstallerPath 'c:\temp\7z.msi' -Certificate 'C:\temp\cert.pfx' -ModulePath 'C:\Program Files\WindowsPowerShell\Modules\Msix-Automation\Msix-Automation.psm1' -CertPasswordRequired

        Example usage when no certificate password is required:
        ConvertTo-MSIXExampleProvideInstaller.ps1 -InstallerPath 'c:\temp\7z.msi' -Certificate 'C:\temp\cert.pfx' -ModulePath 'C:\Program Files\WindowsPowerShell\Modules\Msix-Automation\Msix-Automation.psm1'

    .Notes
        This example specifies not to automatically update Windows Store Apps on the system if winget is not present.
        This example specifies to not automatically install the Windows 10 SDK if it is not installed on the system.
        This example uses an installer that you have already downloaded.
#>

# Parameters
[cmdletbinding()]
param
(
    [Parameter(Mandatory=$true)]
    [ValidateScript({((Test-Path -Path $_) -and ($_.EndsWith('.pfx')))})]
    [String]
    $Certificate,

    [Parameter(Mandatory=$true)]
    [ValidateScript({(Test-Path -Path $_)})]
    [String]
    $InstallerPath,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $ModulePath,

    [Parameter()]
    [Switch]
    $CertPasswordRequired
)

# Set up variables
$appName = '7-Zip'
$msixName = '7-Zip'
$msixPath = 'C:\MSIXPackages'
$publisherDisplayName = 'contoso.com'
$arguments = '/qn'

# Import the requisite module.
Import-Module -Name $ModulePath

# Validate that the required tooling exists on the system
$winget = Confirm-WingetUtility
$msixTool = Confirm-MsixPackagingTool
$sdk = Confirm-Windows10Sdk

# Throw if the appropriate tooling doesn't exist on the system
if ($winget -eq $false)
{
    Throw "The Winget utility is not present, please update your Microsoft Store apps"
}

if ($msixTool -eq $false)
{
    Throw "The MSIX Packaging Tool is not present, please install the tool from the Microsoft Store"
}

if ($sdk -eq $false)
{
    Throw "The MSIX Packaging Tool is not present, please install the tool from the Microsoft Store"
}

# Get the certificate password if required and determine the certificate publisher name
if ($CertPasswordRequired -eq $true)
{
    $password = (Get-Credential -UserName 'DoesntMatter' -Message 'Please enter the password for the .pfx certificate').Password
    $publisherName = Get-CertPublisher -Certificate $Certificate -Password $password
}
else
{
    $publisherName = Get-CertPublisher -Certificate $Certificate
}

# Detect .msi product version
$properties = Get-MSIProperties -path $InstallerPath
[string]$version = $properties.ProductVersion

# Do version translation for .msix handling
[version]$version = $update.LatestVersion
$msixVersion = Format-MsixVersion -Version $version

# Call cleanup for the packaging tool
MsixPackagingTool.exe cleanup
Stop-Service -Name wuauserv -Force

# Convert the installer to msix format
$displayName = "$appName$msixVersion"
ConvertTo-Msix -PackageName $msixName -PackageDisplayName $displayName -PublisherName $publisherName -PublisherDisplayName $publisherDisplayName -Version $msixVersion -InstallerPath "$InstallerPath" -OutputPath $msixPath -Arguments $arguments

if ((Get-ChildItem -Path "C:\MSIXPackages\$displayName").Name -NotContains "$displayName.msix") {
    Throw "MSIX Conversion Failed."
}

Start-Service -Name wuauserv -ErrorAction SilentlyContinue

# Sign MSIX
if ($CertPasswordRequired -eq $true)
{
    Set-MSIXPackageSignature -Certificate $Certificate -MsixFile "$msixPath\$($displayName)\$($displayName).msix" -Password $password
}
else
{
    Set-MSIXPackageSignature -Certificate $Certificate -MsixFile "$msixPath\$($displayName)\$($displayName).msix"
}
