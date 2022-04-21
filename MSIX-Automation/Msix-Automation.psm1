<#
    .SYNOPSIS
        Checks the version of the DesktopAppInstaller utility to determine if the winget utility is
        present. This function will update Windows Store apps if necessary when the Update parameter is
        specified.

        This function will return true if winget is available and false if winget is unavailable on the
        system.

    .PARAMETER Update
        Specifies whether to update Windows Store apps if the DesktopAppInstaller app isn't updated to
        include the winget utility.
#>
function Confirm-WingetUtility(){
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [Switch]
        $Update
    )
    try
    {

        [version]$version = (Get-AppxPackage -Name Microsoft.DesktopAppInstaller).Version

        if ([version]$version -lt 1.2 -and $Update -eq $true)
        {
            Get-CimInstance -Namespace "Root\cimv2\mdm\dmmap" -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" | Invoke-CimMethod -MethodName UpdateScanMethod

            while ([version]$version -lt 1.2)
            {
                [version]$version = (Get-AppxPackage -Name Microsoft.DesktopAppInstaller).Version
                Start-Sleep 30
            }

            return $true
        }
        elseif ([version]$version -ge 1.2)
        {
            return $true
        }
        else
        {
            return $false
        }
    }
    catch
    {
        Write-Error -Message $_.Exception.Message;
    }
}

<#
    .SYNOPSIS
        Checks whether the MSIX Packaging Tool is installed on the system.

        This function will return true if the tool is available and false if the tool is unavailable on the
        system.
#>
function Confirm-MsixPackagingTool(){
    try
    {

        $tool = Get-AppxPackage -Name Microsoft.MsixPackagingTool

        if ($null -eq $tool)
        {
            return $false
        }
        else
        {
            return $true
        }
    }
    catch
    {
        Write-Error -Message $_.Exception.Message;
    }
}

<#
    .SYNOPSIS
        Checks whether the Windows 10 SDK is installed on the system.

        This function will return true if the SDK is available and false if the SDK is unavailable on the
        system. This function will install the SDK if it is not present and the AutoInstall parameter is
        specified.

    .PARAMETER Update
        Specifies whether to update Windows Store apps if the DesktopAppInstaller app isn't updated to
        include the winget utility.

    .Notes
        This function relies on the winget utility included in Windows 11 and Windows 10 as part of the
        Desktop App Installer default appx package.
#>
function Confirm-Windows10Sdk(){
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [Switch]
        $AutoInstall
    )
    try
    {

        $path = Test-Path -Path 'C:\Program Files (x86)\Windows Kits\10'

        if ($path -eq $false -and $AutoInstall -eq $true)
        {
            Winget Install Microsoft.WindowsSDK --Source Winget --Accept-Source-Agreements --Accept-Package-Agreements --Silent

            return $true
        }
        elseif ($path -eq $true)
        {
            return $true
        }
        else
        {
            return $false
        }
    }
    catch
    {
        Write-Error -Message $_.Exception.Message;
    }
}

<#
    .SYNOPSIS
        Queries winget for a specified application and returns the latest version and download link.
        The default source is winget, but a parameter is added for functionality to query other repos.

    .PARAMETER AppName
        Specifies the application name to query get the latest version and download link for.

    .PARAMETER Source
        Specifies the repo that the winget tool will use. Specify this parameter to use a repo other than
        winget if desired.
#>
function Get-NewAppVersionWinget(){
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $AppName,

        [Parameter()]
        [String]
        $Source = "winget"
    )
    try
    {

        $latest = Winget Show $AppName --Source $Source --Accept-Source-Agreements

        if ($latest -Contains "No package found matching input criteria." )
        {
            throw "Winget did not find $AppName. Please check the app name or use the web search function."
        }

        $latestVersion = ($latest | Where-Object -FilterScript {$_ -like 'Version*'}).Split(" ")[1]

        $downloadLink = ($latest | Where-Object -FilterScript {$_ -like '*Download Url:*'}).Split(":",2)[1]

        Return @{
            LatestVersion = $latestVersion
            DownloadLink  = $downloadLink
        }
    }
    catch
    {
        Write-Error -Message $_.Exception.Message;
    }
}

<#
    .SYNOPSIS
        Downloads the installer for a specified application.

    .PARAMETER FileName
        Specifies what to name the downloaded file.

    .PARAMETER DownloadLink
        Specifies the download link for the installer.

    .PARAMETER OutputPath
        Specifies the directory to download the file to.
#>
function Get-Installer(){
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FileName,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DownloadLink,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo]
        $OutputPath
    )
    try {
        if (-Not (Test-Path $OutputPath))
        {
            New-Item -Path $OutputPath -ItemType Directory
        }

        $ProgressPreference = 'SilentlyContinue'

        Invoke-WebRequest -Uri $DownloadLink -OutFile "$OutputPath\$($FileName)"
    }
    catch
    {
        Write-Error -Message $_.Exception.Message;
    }
}

<#
    .SYNOPSIS
        Formats a product version into a format acceptable to the MSIX Packaging Tool

    .PARAMETER Version
        Specifies the product version to format
#>
function Format-MsixVersion(){
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [Version]
        $Version
    )
    try
    {

        $msixVersion = ("$($version.Major).$($version.Minor).$($version.Build).0").Replace("-1","0")

        return $msixVersion
    }
    catch
    {
        Write-Error -Message $_.Exception.Message;
    }
}

<#
    .SYNOPSIS
        Converts an installer to msix format. Please note, this does not sign the resulting .msix.

    .PARAMETER Arguments
        Specifies the command line arguments for a silent install of the given application.

    .PARAMETER InstallerPath
        Specifies the path to the installer file.

    .PARAMETER PackageName
        Specifies what to name the resulting MSIX package.

    .PARAMETER PackageDisplayName
        Specifies what the display name the MSIX package should present.

    .PARAMETER PublisherName
        Specifies the cert subject name for the certificate that will be used to sign the package.

    .PARAMETER Version
        Specifies what version the MSIX package will be.
#>
function ConvertTo-Msix
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [string]
        $Arguments,

        [Parameter()]
        [ValidateScript({(Test-Path -Path $_)})]
        [string]
        $InstallerPath,

        [Parameter()]
        [string]
        $OutputPath,

        [Parameter()]
        [string]
        $PackageName,

        [Parameter()]
        [string]
        $PackageDisplayName,

        [Parameter()]
        [string]
        $PublisherName,

        [Parameter()]
        [string]
        $PublisherDisplayName,

        [Parameter()]
        [string]
        $Version
    )
    try {
        [xml]$xmlTemplate = @'
<?xml version="1.0" encoding="Windows-1252"?>

        <MsixPackagingToolTemplate xmlns="http://schemas.microsoft.com/appx/msixpackagingtool/template/2018">

          <Settings AllowTelemetry="true" ApplyAllPrepareComputerFixes="false" GenerateCommandLineFile="true" AllowPromptForPassword="false" p4:EnforceMicrosoftStoreRequirements="true" p5:ServerPortNumber="1599" p6:AddPackageIntegrity="true" p7:SupportedWindowsVersionForMsixCore="None" xmlns:p7="http://schemas.microsoft.com/msix/msixpackagingtool/template/2004" xmlns:p6="http://schemas.microsoft.com/msix/msixpackagingtool/template/2001" xmlns:p5="http://schemas.microsoft.com/msix/msixpackagingtool/template/1904" xmlns:p4="http://schemas.microsoft.com/msix/msixpackagingtool/template/2007">

            <ExclusionItems>

                <FileExclusion ExcludePath="[{CryptoKeys}]"/>

                <FileExclusion ExcludePath="[{Common AppData}]\Microsoft\Crypto"/>

                <FileExclusion ExcludePath="[{Common AppData}]\Microsoft\Search\Data"/>

                <FileExclusion ExcludePath="[{Cookies}]"/>

                <FileExclusion ExcludePath="[{History}]"/>

                <FileExclusion ExcludePath="[{Cache}]"/>

                <FileExclusion ExcludePath="[{Personal}]"/>

                <FileExclusion ExcludePath="[{Profile}]\Local Settings"/>

                <FileExclusion ExcludePath="[{Profile}]\NTUSER.DAT.LOG1"/>

                <FileExclusion ExcludePath="[{Profile}]\NTUSER.DAT.LOG2"/>

                <FileExclusion ExcludePath="[{Recent}]"/>

                <FileExclusion ExcludePath="[{Windows}]\Debug"/>

                <FileExclusion ExcludePath="[{Windows}]\Logs\CBS"/>

                <FileExclusion ExcludePath="[{Windows}]\Temp"/>

                <FileExclusion ExcludePath="[{Windows}]\WinSxS\ManifestCache"/>

                <FileExclusion ExcludePath="[{Windows}]\WindowsUpdate.log"/>

                <FileExclusion ExcludePath="[{Windows}]\Installer"/>

                <FileExclusion ExcludePath="[{PackageDrive}]\$Recycle.Bin"/>

                <FileExclusion ExcludePath="[{PackageDrive}]\System Volume Information"/>

                <FileExclusion ExcludePath="[{AppData}]\Microsoft\AppV"/>

                <FileExclusion ExcludePath="[{Local AppData}]\Packages"/>

                <FileExclusion ExcludePath="[{Local AppData}]\Temp"/>

                <FileExclusion ExcludePath="[{Local AppData}]\Microsoft\Windows"/>

                <FileExclusion ExcludePath="[{Common AppData}]\Microsoft\Microsoft Security Client"/>

                <FileExclusion ExcludePath="[{Common AppData}]\Microsoft\Microsoft Antimalware"/>

                <FileExclusion ExcludePath="[{Common AppData}]\Microsoft\Windows Defender"/>

                <FileExclusion ExcludePath="[{ProgramFiles}]\Microsoft Security Client"/>

                <FileExclusion ExcludePath="[{ProgramFiles}]\Windows Defender"/>

                <FileExclusion ExcludePath="[{ProgramFiles}]\WindowsApps"/>

                <FileExclusion ExcludePath="[{PackageDrive}]\Config.Msi"/>

                <FileExclusion ExcludePath="[{Local AppData}]\Microsoft\OneDrive"/>

                <FileExclusion ExcludePath="[{Local AppData}]\Temp"/>

                <RegistryExclusion ExcludePath="REGISTRY\MACHINE\SOFTWARE\Wow6432Node\Microsoft\Cryptography"/>

                <RegistryExclusion ExcludePath="REGISTRY\MACHINE\SOFTWARE\Microsoft\Cryptography"/>

                <RegistryExclusion ExcludePath="REGISTRY\MACHINE\SOFTWARE\Microsoft\Microsoft Antimalware"/>

                <RegistryExclusion ExcludePath="REGISTRY\MACHINE\SOFTWARE\Microsoft\Microsoft Antimalware Setup"/>

                <RegistryExclusion ExcludePath="REGISTRY\MACHINE\SOFTWARE\Microsoft\Microsoft Security Client"/>

                <RegistryExclusion ExcludePath="REGISTRY\MACHINE\SOFTWARE\Policies\Microsoft\Microsoft Antimalware"/>

                <RegistryExclusion ExcludePath="REGISTRY\MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender"/>

                <RegistryExclusion ExcludePath="REGISTRY\USER\[{CurrentUserSID}]\Software\Microsoft\Windows\CurrentVersion\Explorer\StreamMRU"/>

                <RegistryExclusion ExcludePath="REGISTRY\USER\[{CurrentUserSID}]\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\StreamMRU"/>

                <RegistryExclusion ExcludePath="REGISTRY\USER\[{CurrentUserSID}]\Software\Microsoft\Windows\CurrentVersion\Explorer\Streams"/>

                <RegistryExclusion ExcludePath="REGISTRY\USER\[{CurrentUserSID}]\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Streams"/>

                <RegistryExclusion ExcludePath="REGISTRY\MACHINE\SOFTWARE\Microsoft\AppV"/>

                <RegistryExclusion ExcludePath="REGISTRY\MACHINE\SOFTWARE\Wow6432Node\Microsoft\AppV"/>

                <RegistryExclusion ExcludePath="REGISTRY\USER\[{CurrentUserSID}]\Software\Microsoft\AppV"/>

                <RegistryExclusion ExcludePath="REGISTRY\USER\[{CurrentUserSID}]\Software\Wow6432Node\Microsoft\AppV"/>

                <RegistryExclusion ExcludePath="REGISTRY\USER\[{CurrentUserSID}]_Classes\AppID\OneDrive.EXE"/>

                <RegistryExclusion ExcludePath="REGISTRY\USER\[{CurrentUserSID}]_Classes\OOBERequestHandler.OOBERequestHandler"/>

                <RegistryExclusion ExcludePath="REGISTRY\USER\[{CurrentUserSID}]_Classes\SyncEngineFileInfoProvider.SyncEngineFileInfoProvider"/>

            </ExclusionItems>

          </Settings>

          <PrepareComputer DisableWindowsSearchService="false" DisableSmsHostService="true" DisableWindowsUpdateService="true" />

          <SaveLocation PackagePath="temp" />

          <Installer Path="temp" Arguments="temp" />

          <PackageInformation PackageName="temp" PackageDisplayName="temp" PublisherName="CN=temp" PublisherDisplayName="temp" Version="temp" />

        </MsixPackagingToolTemplate>
'@

        if (-Not (Test-Path $OutputPath))
        {
            New-Item -Path $OutputPath -ItemType Directory
        }

        $savePath = "$OutputPath\$($PackageDisplayName)\$($PackageDisplayName).msix"

        [xml]$apptemplate = [xml]$xmlTemplate
        $apptemplate.MsixPackagingToolTemplate.SaveLocation.PackagePath = $savePath
        $apptemplate.MsixPackagingToolTemplate.Installer.Path = $InstallerPath
        $apptemplate.MsixPackagingToolTemplate.Installer.Arguments = $Arguments
        $apptemplate.MsixPackagingToolTemplate.PackageInformation.PackageName = $PackageName
        $apptemplate.MsixPackagingToolTemplate.PackageInformation.PackageDisplayName = $PackageDisplayName
        $apptemplate.MsixPackagingToolTemplate.PackageInformation.PublisherName = $PublisherName
        $apptemplate.MsixPackagingToolTemplate.PackageInformation.PublisherDisplayName = $PublisherDisplayName
        $apptemplate.MsixPackagingToolTemplate.PackageInformation.Version = $Version

        $apptemplate.Save("$OutputPath\temp.xml")
        msixpackagingtool create-package --template "$OutputPath\temp.xml"

        #CleanUp
        Remove-Item -Path "$OutputPath\temp.xml"
    }
    catch
    {
        Write-Error -Message $_.Exception.Message;
    }
}

<#
    .SYNOPSIS
        Makes a copy of an existing MSIX package, and unzips it for editing the contents.

    .PARAMETER Path
        Specifies the path to an .msix file.

    .PARAMETER TempDir
        Specifies a directory to use as a temporary directory, in which to copy and unpack the
        .msix file.
#>
function Open-Msix(){

    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [ValidateScript({((Test-Path -Path $_) -and ($_.EndsWith('.msix')))})]
        [String]
        $Path,

        [parameter(Mandatory=$true)]
        [String]
        $OutputPath
    )
    try {
        if (-Not (Test-Path "$OutputPath"))
        {
            New-Item "$OutputPath" -ItemType Directory
        }

        $package = Get-Item -Path $Path
        Copy-Item -Path $package.FullName -Destination "$OutputPath\$($package.BaseName).zip"
        Expand-Archive -Path "$OutputPath\$($package.BaseName).zip" -DestinationPath "$OutputPath\$($package.BaseName)"

        # Return unzipped msix path
        return "$OutputPath\$($package.BaseName)"
    }

    catch
    {
        Write-Error -Message $_.Exception.Message;
        break;
    }
}

<#
    .SYNOPSIS
        Signs a specified .msix file with the specified pfx certificate. Use the password parameter
        if the .pfx requires a password. This function only supports SHA256 certs at this time.

    .PARAMETER Certificate
        Specifies the full path to the .pfx file that will be used to sign the .msix.

    .PARAMETER MsixFile
        Specifies the full path to the .msix file to sign.

    .PARAMETER Password
        Specifies a password if required for the .pfx certificate.
#>
function Set-MSIXPackageSignature(){
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateScript({((Test-Path -Path $_) -and ($_.EndsWith('.pfx')))})]
        [String]
        $Certificate,

        [Parameter(Mandatory=$true)]
        [ValidateScript({((Test-Path -Path $_) -and ($_.EndsWith('.msix')))})]
        [String]
        $MsixFile,

        [Parameter()]
        [Security.SecureString]
        $Password
    )
    try {
        # Determine path to signtool.exe and throw if not present
        $tool = Get-ChildItem -Path 'C:\Program Files (x86)\Windows Kits\10' -Filter 'signtool.exe' -Recurse | Select-Object -Property FullName | Where-Object -FilterScript {$_.FullName -match 'x64'}

        if ($tool.FullName.Count -gt 1)
        {
            $signtool = $tool.FullName[0]
        }
        elseif ($tool.FullName.Count -eq 0)
        {
            throw "Signtool.exe was not found. Please validate your Windows 10 SDK Installation."
        }
        else
        {
            $signtool = $tool.FullName
        }

        # Sign Packages
        if ([string]::IsNullOrEmpty($Password))
        {
            & $signtool sign /fd sha256 /a /f $Certificate $MsixFile
        }
        else
        {
            # Check for cert in machine publisher store and add if not present
            $publisher = Get-CertPublisher -Certificate $Certificate -Password $Password
            $cert = (dir Cert:\LocalMachine\my\ -CodeSigningCert) | Where-Object -FilterScript {$_.Subject -match "$publisher"}

            if ($null -eq $cert)
            {
                Import-PfxCertificate -Exportable -Password $Password -FilePath $Certificate -CertStoreLocation Cert:\LocalMachine\My
            }

            # Sign the MSIX
            & $signtool sign /sm /fd sha256 /a /n $SubjectName $MsixFile
        }
    }

    catch {
        Write-Error -Message $_.Exception.Message;
        break;
    }
}

<#
    .SYNOPSIS
        This function leverages the makeappx.exe tool in the Windows 10 SDK to repackage unzipped
        MSIX files after required edits are completed.

    .PARAMETER InputPath
        Specifies the full path to the unzipped MSIX files that you wish to repackage as an msix.
#>
function Save-MsixFromUnpacked(){
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateScript({(Test-Path -Path $_)})]
        [String]
        $InputPath
    )
    try {
        # Identify the path for makeappx.exe
        $tool = Get-ChildItem -Path "C:\Program Files (x86)\Windows Kits\10" -Filter 'makeappx.exe' -Recurse | Select-Object -Property FullName | Where-Object -FilterScript {$_.FullName -match 'x64'}

        if ($tool.FullName.Count -gt 1)
        {
            $makeAppx = $tool.FullName[0]
        }
        elseif ($tool.FullName.Count -eq 0)
        {
            Throw "makeappx.exe was not found. Please validate your Windows 10 SDK Installation"
        }
        else
        {
            $makeAppx = $tool.FullName
        }

        # Repackage into MSIX
        & $makeAppx pack /d $InputPath /p "$InputPath.msix"
    }

    catch {
        Write-Error -Message $_.Exception.Message;
        break;
    }
}

<#
    .SYNOPSIS
        This function pulls properties out of an MSI file.

    .PARAMETER Path
        Specifies the full path to the .msi file to get the properties from.
#>
function Get-MSIProperties {
    param
    (
      [Parameter(Mandatory=$true)]
      [ValidateNotNullOrEmpty()]
      [System.IO.FileInfo]
      $Path
    )
    begin {
        $windowsInstaller = (New-Object -ComObject WindowsInstaller.Installer)
    }
    process
    {
        $properties = @('ProductCode', 'ProductVersion', 'ProductName', 'Manufacturer', 'ProductLanguage')
        $table = @{}
        $msi = $windowsInstaller.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $windowsInstaller, @($Path.FullName, 0))
        foreach ($property in $properties) {
            try
            {
                $view = $msi.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $msi, ("SELECT Value FROM Property WHERE Property = '$($property)'"))
                $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
                $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
                $table.Add($property, $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, 1))
            }
            catch
            {
                $table.Add($property, $null)
            }
        }
        $msi.GetType().InvokeMember('Commit', 'InvokeMethod', $null, $msi, $null)
        $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null)
        $msi = $null
        $view = $null
        return $table
    }
    end
    {
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($windowsInstaller) | Out-Null
        return [System.GC]::Collect()
    }
}

<#
    .SYNOPSIS
        This function resolves the publisher from a given .pfx certificate

    .PARAMETER Certificate
        Specifies the full path to the .pfx file to get the publisher from.
#>
function Get-CertPublisher(){
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateScript({((Test-Path -Path $_) -and ($_.EndsWith('.pfx')))})]
        [String]
        $Certificate,

        [Parameter()]
        [Security.SecureString]
        $Password
    )
    try {
        if ([string]::IsNullOrEmpty($Password))
        {
            $data = Get-PfxData -FilePath $Certificate
            $publisher = $data.EndEntityCertificates.Subject

            return $publisher
        }
        else
        {
            $data = Get-PfxData -FilePath $Certificate -Password $Password
            $publisher = $data.EndEntityCertificates.Subject

            return $publisher
        }
    }

    catch {
        Write-Error -Message $_.Exception.Message;
        break;
    }
}
