<#
.COPYRIGHT
	Copyright (c) Microsoft Corporation. All rights reserved.
	Licensed under the MIT license.
	See LICENSE in the project root for license information.
#>

<#
	.SYNOPSIS
		This function is used to authenticate with the Graph API REST interface

	.DESCRIPTION
		The function authenticate with the Graph API Interface with the tenant name

	.EXAMPLE
		Get-AuthToken

	Authenticates you with the Graph API interface
#>
function Get-AuthToken {
	[CmdletBinding()]
	param
	(
	    [Parameter(Mandatory=$true)]
	    $User
	)

	$userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
	$tenant = $userUpn.Host

	Write-Host "Checking for AzureAD module..."
	$aadModule = Get-Module -Name "AzureAD" -ListAvailable

	if ($aadModule -eq $null)
	{
	    Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
	    $aadModule = Get-Module -Name "AzureADPreview" -ListAvailable
	}

	if ($aadModule -eq $null)
	{
	    Write-Host
	    Write-Host "AzureAD Powershell module not installed..." -f Red
	    Write-Host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
	    Write-Host "Script can't continue..." -f Red
	    Write-Host
	    exit
	}

	# Getting path to ActiveDirectory Assemblies
	# If the module count is greater than 1 find the latest version
	if($aadModule.count -gt 1)
	{
	    $latestVersion = ($aadModule | Select Version | Sort-Object)[-1]
	    $aadModule = $AadModule | ? { $_.Version -eq $latestVersion.Version }
	    # Checking if there are multiple versions of the same module found
	    if($aadModule.count -gt 1)
	    {
	        $aadModule = $aadModule | Select -Unique
	    }

	    $adal = Join-Path $aadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
	    $adalforms = Join-Path $aadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
	}
    else
    {
        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    }

	[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
	[System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

	$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
	$redirectUri = "urn:ietf:wg:oauth:2.0:oob"
	$resourceAppIdURI = "https://graph.microsoft.com"
	$authority = "https://login.microsoftonline.com/$Tenant"

    try
    {
	    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

	    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
	    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
	    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
	    $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
	    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result

        # If the accesstoken is valid then create the authentication header
        if($authResult.AccessToken)
        {
	        # Creating header for Authorization token
	        $authHeader = @{
	            'Content-Type'='application/json'
	            'Authorization'="Bearer " + $authResult.AccessToken
	            'ExpiresOn'=$authResult.ExpiresOn
	        }
	        return $authHeader
        }
        else {
	        Write-Host
	        Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
	        Write-Host
	        break
        }
    }
    catch
    {
	    write-host $_.Exception.Message -f Red
	    write-host $_.Exception.ItemName -f Red
	    write-host
	    break
    }
}
####################################################

function Copy-Object($Object){
	$stream = New-Object IO.MemoryStream;
	$formatter = New-Object Runtime.Serialization.Formatters.Binary.BinaryFormatter;
	$formatter.Serialize($stream, $Object);
	$stream.Position = 0;
	$formatter.Deserialize($stream);
}
####################################################

function Set-Headers($AuthToken){
	foreach ($header in $AuthToken.GetEnumerator())
	{
		if ($header.Name.ToLower() -eq "authorization")
		{
			continue;
		}
		Write-Host -ForegroundColor Gray "$($header.Name): $($header.Value)";
	}
}
####################################################

function Send-GetRequest($CollectionPath){
	$uri = "$baseUrl$CollectionPath";
	$request = "GET $uri";

	if ($logRequestUris)
	{
		Write-Host $request;
	}

	if ($logHeaders)
	{
		Set-Headers $authToken;
	}

	try
	{
		$response = Invoke-RestMethod $uri -Method Get -Headers $authToken;
		$response;
	}
	catch
	{
		Write-Host -ForegroundColor Red $request;
		Write-Host -ForegroundColor Red $_.Exception.Message;
		throw;
	}
}
####################################################

function Send-PatchRequest($CollectionPath, $Body){
	Send-Request "PATCH" $CollectionPath $Body;
}
####################################################

function Send-PostRequest($CollectionPath, $Body){
	Send-Request "POST" $CollectionPath $Body;
}
####################################################

function Send-Request($Verb, $CollectionPath, $Body){

	$uri = "$baseUrl$CollectionPath";
	$request = "$Verb $uri";
	$clonedHeaders = Copy-Object $authToken;
	$clonedHeaders["content-length"] = $Body.Length;
	$clonedHeaders["content-type"] = "application/json";

	if ($logRequestUris)
	{
		Write-Host $request;
	}

	if ($logHeaders)
	{
		Set-Headers $clonedHeaders;
	}

	if ($logContent)
	{
		Write-Host -ForegroundColor Gray $Body;
	}

	try
	{
		$response = Invoke-RestMethod $uri -Method $Verb -Headers $clonedHeaders -Body $Body;
		$response;
	}
	catch
	{
		Write-Host -ForegroundColor Red $request;
		Write-Host -ForegroundColor Red $_.Exception.Message;
		throw;
	}
}
####################################################

function Write-AzureStorageChunk($SasUri, $ID, $Body){
	$uri = "$SasUri&comp=block&blockid=$ID";
	$request = "PUT $uri";

	$iso = [System.Text.Encoding]::GetEncoding("iso-8859-1");
	$encodedBody = $iso.GetString($Body);
	$headers = @{
		"x-ms-blob-type" = "BlockBlob"
	};

	if ($logRequestUris)
	{
		Write-Host $request;
	}

	if ($logHeaders)
	{
		Set-Headers $headers;
	}

	try
	{
		$response = Invoke-WebRequest $uri -Method Put -Headers $headers -Body $encodedBody;
	}
	catch
	{
		Write-Host -ForegroundColor Red $request;
		Write-Host -ForegroundColor Red $_.Exception.Message;
		throw;
	}
}
####################################################

function Complete-AzureStorageUpload($SasUri, $Ids){
	$uri = "$SasUri&comp=blocklist";
	$request = "PUT $uri";

	$xml = '<?xml version="1.0" encoding="utf-8"?><BlockList>';
	foreach ($id in $Ids)
	{
		$xml += "<Latest>$id</Latest>";
	}

	$xml += '</BlockList>';
	if ($logRequestUris)
	{
		Write-Host $request;
	}
	if ($logContent)
	{
		Write-Host -ForegroundColor Gray $xml;
	}

	try
	{
		Invoke-RestMethod $uri -Method Put -Body $xml;
	}
	catch
	{
		Write-Host -ForegroundColor Red $request;
		Write-Host -ForegroundColor Red $_.Exception.Message;
		throw;
	}
}
####################################################

function Send-FileToAzureStorage($SasUri, $Filepath){

	# Chunk size = 1 MiB
    $chunkSizeInBytes = 1024 * 1024;

	# Read the whole file and find the total chunks.
	#[byte[]]$bytes = Get-Content $filepath -Encoding byte;
    # Using ReadAllBytes method as the Get-Content used alot of memory on the machine
    [byte[]]$bytes = [System.IO.File]::ReadAllBytes($Filepath);
	$chunks = [Math]::Ceiling($bytes.Length / $chunkSizeInBytes);

	# Upload each chunk.
	$ids = @();
    $cc = 1

	for ($chunk = 0; $chunk -lt $chunks; $chunk++)
	{
        $id = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($chunk.ToString("0000")));
		$ids += $id;

		$start = $chunk * $chunkSizeInBytes;
		$end = [Math]::Min($start + $chunkSizeInBytes - 1, $bytes.Length - 1);
		$body = $bytes[$start..$end];

        Write-Progress -Activity "Uploading File to Azure Storage" -Status "Uploading chunk $cc of $chunks" `
        -PercentComplete ($cc / $chunks*100)
        $cc++

        $uploadResponse = Write-AzureStorageChunk $SasUri $id $body;
	}

    Write-Progress -Completed -Activity "Uploading File to Azure Storage"
    Write-Host

	# Finalize the upload.
	$uploadResponse = Complete-AzureStorageUpload $sasUri $ids;
}
####################################################

function Add-Key{
	try
	{
		$aes = [System.Security.Cryptography.Aes]::Create();
        $aesProvider = New-Object System.Security.Cryptography.AesCryptoServiceProvider;
        $aesProvider.GenerateKey();
        $aesProvider.Key;
	}
	finally
	{
		if ($aesProvider -ne $null)
		{
			$aesProvider.Dispose();
		}
		if ($aes -ne $null) {
			$aes.Dispose();
		}
	}
}
####################################################

function Add-IV{

	try
	{
		$aes = [System.Security.Cryptography.Aes]::Create();
        $aes.IV;
	}
	finally
	{
		if ($aes -ne $null) {
			$aes.Dispose();
		}
	}
}
####################################################

function Set-IVEncryption($SourceFile, $TargetFile, $EncryptionKey, $HmacKey, $InitializationVector){

	$bufferBlockSize = 1024 * 4;
	$computedMac = $null;

	try
	{
		$aes = [System.Security.Cryptography.Aes]::Create();
		$hmacSha256 = New-Object System.Security.Cryptography.HMACSHA256;
		$hmacSha256.Key = $HmacKey;
		$hmacLength = $hmacSha256.HashSize / 8;
		$buffer = New-Object byte[] $bufferBlockSize;
		$bytesRead = 0;
		$targetStream = [System.IO.File]::Open($targetFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read);
		$targetStream.Write($buffer, 0, $hmacLength + $InitializationVector.Length);

		try
		{
			$encryptor = $aes.CreateEncryptor($EncryptionKey, $InitializationVector);
			$sourceStream = [System.IO.File]::Open($SourceFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read);
			$cryptoStream = New-Object System.Security.Cryptography.CryptoStream -ArgumentList @($targetStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write);
			$targetStream = $null;
			while (($bytesRead = $sourceStream.Read($buffer, 0, $bufferBlockSize)) -gt 0)
			{
				$cryptoStream.Write($buffer, 0, $bytesRead);
				$cryptoStream.Flush();
			}
			$cryptoStream.FlushFinalBlock();
		}
		finally
		{
			if ($cryptoStream -ne $null)
			{
				$cryptoStream.Dispose();
			}
			if ($sourceStream -ne $null)
			{
				$sourceStream.Dispose();
			}
			if ($encryptor -ne $null)
			{
				$encryptor.Dispose();
			}
		}

		try
		{
			$finalStream = [System.IO.File]::Open($TargetFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::Read)

			$finalStream.Seek($hmacLength, [System.IO.SeekOrigin]::Begin) > $null;
			$finalStream.Write($InitializationVector, 0, $InitializationVector.Length);
			$finalStream.Seek($hmacLength, [System.IO.SeekOrigin]::Begin) > $null;

			$hmac = $hmacSha256.ComputeHash($finalStream);
			$computedMac = $hmac;

			$finalStream.Seek(0, [System.IO.SeekOrigin]::Begin) > $null;
			$finalStream.Write($hmac, 0, $hmac.Length);
		}
		finally
		{
			if ($finalStream -ne $null) {
				$finalStream.Dispose();
			}
		}
	}
	finally
	{
		if ($targetStream -ne $null)
		{
			$targetStream.Dispose();
		}
        if ($aes -ne $null)
        {
            $aes.Dispose();
        }
	}

	$computedMac;
}
####################################################

function Set-FileEncryption($SourceFile, $TargetFile){

	$encryptionKey = Add-Key;
	$hmacKey = Add-Key;
	$initializationVector = Add-IV;

	# Create the encrypted target file and compute the HMAC value.
	$mac = Set-IVEncryption $SourceFile $TargetFile $encryptionKey $hmacKey $initializationVector;

	# Compute the SHA256 hash of the source file and convert the result to bytes.
	$fileDigest = (Get-FileHash $sourceFile -Algorithm SHA256).Hash;
	$fileDigestBytes = New-Object byte[] ($fileDigest.Length / 2);
    for ($i = 0; $i -lt $fileDigest.Length; $i += 2)
	{
        $fileDigestBytes[$i / 2] = [System.Convert]::ToByte($fileDigest.Substring($i, 2), 16);
    }

	# Return an object that will serialize correctly to the file commit Graph API.
	$encryptionInfo = @{};
	$encryptionInfo.encryptionKey = [System.Convert]::ToBase64String($encryptionKey);
	$encryptionInfo.macKey = [System.Convert]::ToBase64String($hmacKey);
	$encryptionInfo.initializationVector = [System.Convert]::ToBase64String($initializationVector);
	$encryptionInfo.mac = [System.Convert]::ToBase64String($mac);
	$encryptionInfo.profileIdentifier = "ProfileVersion1";
	$encryptionInfo.fileDigest = [System.Convert]::ToBase64String($fileDigestBytes);
	$encryptionInfo.fileDigestAlgorithm = "SHA256";
	$fileEncryptionInfo = @{};
	$fileEncryptionInfo.fileEncryptionInfo = $encryptionInfo;
	$fileEncryptionInfo;
}
####################################################

function Wait-FileProcessing($FileUri, $Stage){
	$attempts= 60;
	$waitTimeInSeconds = 1;
	$successState = "$($Stage)Success";
	$pendingState = "$($Stage)Pending";
	$failedState = "$($Stage)Failed";
	$timedOutState = "$($Stage)TimedOut";
	$file = $null;
	while ($attempts -gt 0)
	{
		$file = Send-GetRequest $FileUri;

		if ($file.uploadState -eq $successState)
		{
			break;
		}
		elseif ($file.uploadState -ne $pendingState)
		{
			throw "File upload state is not success: $($file.uploadState)";
		}
		Start-Sleep $waitTimeInSeconds;
		$attempts--;
	}

	if ($file -eq $null)
	{
		throw "File request did not complete in the allotted time.";
	}
	$file;
}
####################################################

function Get-AppFileBody($Name, $Size, $SizeEncrypted, $Manifest){

	$body = @{ "@odata.type" = "#microsoft.graph.mobileAppContentFile" };
	$body.name = $Name;
	$body.size = $Size;
	$body.sizeEncrypted = $SizeEncrypted;
	$body.manifest = $Manifest;
	$body;
}
####################################################

function Get-AppCommitBody($ContentVersionId, $LobType){

	$body = @{ "@odata.type" = "#$LobType" };
	$body.committedContentVersion = $ContentVersionId;
	$body;
}
####################################################

function Test-SourceFile(){
param
(
	[parameter(Mandatory=$true)]
	[ValidateNotNullOrEmpty()]
    $SourceFile
)
    try
    {

        if(!(test-path "$SourceFile"))
        {
            Write-Host "Source File '$sourceFile' doesn't exist..." -ForegroundColor Red
            throw
        }
    }
    catch
    {
		Write-Host -ForegroundColor Red $_.Exception.Message;
        Write-Host
		break;
    }
}
####################################################

function Get-MSIXManifest(){

param(
	[parameter(Mandatory=$true)]
	[ValidateNotNullOrEmpty()]
	[System.IO.FileInfo]
	$Path
)

	try {
        Test-SourceFile "c:\temp"
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $tempZip = 'c:\temp\tempZip.zip'
        copy-item -Path $Path -Destination $tempZip
        $zip = [System.IO.Compression.ZipFile]::OpenRead($tempZip)
        $manifest = $zip.Entries | Where-Object { $_.FullName -like 'AppxManifest.xml' }
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($manifest, 'c:\temp\manifest.xml', $true)
        $zip.Dispose()
		[xml]$xml = get-content -Path 'c:\temp\manifest.xml'
        Remove-Item -Path 'c:\temp\manifest.xml'
        Remove-Item -Path $tempZip

        # Return the value
        return $xml
	}
	catch {
	    Write-Warning -Message $_.Exception.Message;
        break;
    }
}
####################################################

function Get-MsixPublisherId(){

param(
	[parameter(Mandatory=$true)]
	[ValidateNotNullOrEmpty()]
	[string]
	$Publisher
)

    $EncUTF16LE = [system.Text.Encoding]::Unicode
    $EncSha256 = [System.Security.Cryptography.HashAlgorithm]::Create("SHA256")

    # Convert to UTF16 Little Endian
    $UTF16LE = $EncUTF16LE.GetBytes($Publisher)

    # Calculate SHA256 hash on UTF16LE Byte array. Store first 8 bytes in new Byte Array
    $Bytes = @()
    (($EncSha256.ComputeHasH($UTF16LE))[0..7]) | % { $Bytes += '{0:x2}' -f $_ }

    # Convert Byte Array to Binary string; Adding padding zeros on end to it has 13*5 bytes
    $BytesAsBinaryString = -join $Bytes.ForEach{ [convert]::tostring([convert]::ToByte($_,16),2).padleft(8,'0') }
    $BytesAsBinaryString = $BytesAsBinaryString.PadRight(65,'0')

    # Crockford Base32 encode. Read each 5 bits; convert to decimal. Lookup position in lookup table
    $Coded = $null
    for ($i=0;$i -lt (($BytesAsBinaryString.Length)); $i+=5)
    {
        $String = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
        [int]$Int = [convert]::Toint32($BytesAsBinaryString.Substring($i,5),2)
        $Coded += $String.Substring($Int,1)
    }
    return $Coded.tolower()
}
####################################################

function Get-MsixFileInformation(){

param(
	[parameter(Mandatory=$true)]
	[ValidateNotNullOrEmpty()]
	[System.IO.FileInfo]
	$Path,

	[parameter(Mandatory=$true)]
	[ValidateNotNullOrEmpty()]
	[ValidateSet("DisplayName", "Description", "Publisher", "IdentityVersion", "PublisherHash", "IdentityName")]
	[string]
	$Property
)

	try {
        [xml]$xml = Get-MSIXManifest -Path $Path

        switch ($Property) {
            'DisplayName'     { $Value = $Xml.Package.Properties.DisplayName }
            'Description'     { $Value = $Xml.Package.Applications.Application.VisualElements.Description }
            'Publisher'       { $Value = $Xml.Package.Properties.PublisherDisplayName }
            'IdentityVersion' { $Value = $Xml.Package.Identity.Version }
            'PublisherHash'   { $Value = Get-MsixPublisherId -Publisher $Xml.Package.Identity.Publisher }
            'IdentityName'    { $Value = $Xml.Package.Identity.Name }
        }

		# Return the value
		return $Value
	}

	catch {
	    Write-Warning -Message $_.Exception.Message;
        break;
    }
}
####################################################

function Get-MSIXAppBody($DisplayName, $Description, $Publisher, $Filename, $IdentityVersion, $IdentityName, $IdentityPublisherHash){

    $supportedOS = @{v8_0 = $false ; v8_1 = $false ; v10_0 = $true}

	$body = @{ "@odata.type" = "#microsoft.graph.windowsUniversalAppX" };
	$body.displayName = $DisplayName;
    $body.description = $Description;
	$body.publisher = $Publisher;
    $body.largeIcon = $null;
    $body.isFeatured = $false;
    $body.privacyInformationUrl = "";
    $body.informationUrl = $null;
    $body.owner = "";
    $body.developer = "";
	$body.notes = "";
	$body.fileName = $Filename;
    $body.applicableArchitectures = "x64";
    $body.applicableDeviceTypes = "desktop";
    $body.identityName = $IdentityName;
    $body.identityPublisherHash = $IdentityPublisherHash;
	$body.identityVersion = $IdentityVersion;
    $body.minimumSupportedOperatingSystem = $supportedOS

	$body;
}
####################################################

<#
	.SYNOPSIS
		This function is used to upload an MSIX LOB Application to the Intune Service

	.DESCRIPTION
		This function is used to upload an MSIX LOB Application to the Intune Service

	.EXAMPLE
		Set-MsixLobUpload -SourceFile "C:\temp\Orca.Msix"

		This example uses all parameters required to add an MSIX Application into the Intune Service
#>
function Set-MsixLobUpload(){
	[cmdletbinding()]
	param
	(
		[parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
	    [string]
	    $SourceFile
	)

	try	{
        $LOBType = "microsoft.graph.windowsUniversalAppX"
        Write-Host "Testing if SourceFile '$SourceFile' Path is valid..." -ForegroundColor Yellow
        Test-SourceFile "$SourceFile"
        $MSIXPath = "$SourceFile"

        # Creating temp file name from Source File path
        $tempFile = [System.IO.Path]::GetDirectoryName("$SourceFile") + "\" + [System.IO.Path]::GetFileNameWithoutExtension("$SourceFile") + "_temp.bin"
        Write-Host
        Write-Host "Creating JSON data to pass to the service..." -ForegroundColor Yellow
        $FileName = [System.IO.Path]::GetFileName("$MSIXPath")
        $DN = (Get-MsixFileInformation -Path "$SourceFile" -Property DisplayName | Out-String).Trimend()
        $DE = (Get-MsixFileInformation -Path "$SourceFile" -Property Description | Out-String).Trimend()
        $PB = (Get-MsixFileInformation -Path "$SourceFile" -Property Publisher | Out-String).Trimend()
        $IV = (Get-MsixFileInformation -Path "$SourceFile" -Property IdentityVersion | Out-String).Trimend()
        $PH = (Get-MsixFileInformation -Path "$SourceFile" -Property PublisherHash | Out-String).Trimend()
        $IN = (Get-MsixFileInformation -Path "$SourceFile" -Property IdentityName | Out-String).Trimend()

		# Create a new MSI LOB app.
		$mobileAppBody = Get-MSIXAppBody -DisplayName "$DN" -Description "$DE" -Publisher "$PB" -Filename "$FileName" -IdentityVersion "$IV" -IdentityName "$IN" -IdentityPublisherHash "$PH"

        Write-Host
        Write-Host "Creating application in Intune..." -ForegroundColor Yellow
		$mobileApp = Send-PostRequest "mobileApps" ($mobileAppBody | ConvertTo-Json);

		# Get the content version for the new app (this will always be 1 until the new app is committed).
        Write-Host
        Write-Host "Creating Content Version in the service for the application..." -ForegroundColor Yellow
		$appId = $mobileApp.id;
		$contentVersionUri = "mobileApps/$appId/$LOBType/contentVersions";
		$contentVersion = Send-PostRequest $contentVersionUri "{}";

        # Encrypt file and Get File Information
        Write-Host
        Write-Host "Ecrypting the file '$SourceFile'..." -ForegroundColor Yellow
        $encryptionInfo = Set-FileEncryption $SourceFile $tempFile;
        $size = (Get-Item "$SourceFile").Length
        $encrySize = (Get-Item "$tempFile").Length

        Write-Host
        Write-Host "Creating the manifest file used to install the application on the device..." -ForegroundColor Yellow

        # Get Manifest File Info
        [xml]$manifestXML = Get-MSIXManifest -Path $SourceFile

        $manifestXML_Output = $manifestXML.OuterXml.ToString()

        $bytes = [System.Text.Encoding]::ASCII.GetBytes($manifestXML_Output)
        $encodedText =[Convert]::ToBase64String($bytes)

		# Create a new file for the app.
        Write-Host
        Write-Host "Creating a new file entry in Azure for the upload..." -ForegroundColor Yellow
		$contentVersionId = $contentVersion.id;
		$fileBody = Get-AppFileBody "$fileName" $size $encrySize "$encodedText";
		$filesUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files";
		$file = Send-PostRequest $filesUri ($fileBody | ConvertTo-Json);

		# Wait for the service to process the new file request.
        Write-Host
        Write-Host "Waiting for the file entry URI to be created..." -ForegroundColor Yellow
		$fileId = $file.id;
		$fileUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId";
		$file = Wait-FileProcessing $fileUri "AzureStorageUriRequest";

		# Upload the content to Azure Storage.
        Write-Host
        Write-Host "Uploading file to Azure Storage..." -f Yellow
		$sasUri = $file.azureStorageUri;
		Send-FileToAzureStorage $file.azureStorageUri $tempFile;

		# Commit the file.
        Write-Host
        Write-Host "Committing the file into Azure Storage..." -ForegroundColor Yellow
		$commitFileUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId/commit";
		Send-PostRequest $commitFileUri ($encryptionInfo | ConvertTo-Json);

		# Wait for the service to process the commit file request.
        Write-Host
        Write-Host "Waiting for the service to process the commit file request..." -ForegroundColor Yellow
		$file = Wait-FileProcessing $fileUri "CommitFile";

		# Commit the app.
        Write-Host
        Write-Host "Committing the file into Azure Storage..." -ForegroundColor Yellow
		$commitAppUri = "mobileApps/$appId";
		$commitAppBody = Get-AppCommitBody $contentVersionId $LOBType;
		Send-PatchRequest $commitAppUri ($commitAppBody | ConvertTo-Json);

        Write-Host "Removing Temporary file '$tempFile'..." -f Gray
        Remove-Item -Path "$tempFile" -Force
        Write-Host

        Write-Host "Sleeping for $sleep seconds to allow patch completion..." -f Magenta
        Start-Sleep $sleep
        Write-Host

	}
    catch
    {
		Write-Host "";
		Write-Host -ForegroundColor Red "Aborting with exception: $($_.Exception.ToString())";
    }
}
####################################################

<#
	.SYNOPSIS
		This function is used to update an existing MSIX LOB Application in the Intune Service
	.DESCRIPTION
		This function is used to update an existing MSIX LOB Application in the Intune Service
	.EXAMPLE
		Set-MsixLobUpdate -SourceFile "C:\temp\Orca.Msix" -DisplayName "Orca"

		This example uses all parameters required to update an existing MSIX Application in the Intune Service

	.Notes
		The DisplayName parameter specifies the DisplayName of the app in Intune that you wish to update.
#>
function Set-MsixLobUpdate(){
	[cmdletbinding()]
	param
	(
		[parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]
	    [string]
	    $SourceFile,

	    [parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$DisplayName
	)

	try	{
        $LOBType = "microsoft.graph.windowsUniversalAppX"

        Write-Host "Testing if SourceFile '$SourceFile' Path is valid..." -ForegroundColor Yellow
        Test-SourceFile "$SourceFile"
        $MSIXPath = "$SourceFile"

        # Creating temp file name from Source File path
        $tempFile = [System.IO.Path]::GetDirectoryName("$SourceFile") + "\" + [System.IO.Path]::GetFileNameWithoutExtension("$SourceFile") + "_temp.bin"

        # Get information about the App to Update
        $app = ((Send-GetRequest -collectionPath 'mobileApps').Value | Where-Object -FilterScript {$_.Displayname -eq $DisplayName})
        $appId = $app.Id

        #Update the LOB.
        Write-Host "Updating the LOB app properties..." -ForegroundColor Yellow
        $FileName = [System.IO.Path]::GetFileName("$MSIXPath")
        $DN = (Get-MsixFileInformation -Path "$SourceFile" -Property DisplayName | Out-String).Trimend()
        $DE = (Get-MsixFileInformation -Path "$SourceFile" -Property Description | Out-String).Trimend()
        $PB = (Get-MsixFileInformation -Path "$SourceFile" -Property Publisher | Out-String).Trimend()
        $IV = (Get-MsixFileInformation -Path "$SourceFile" -Property IdentityVersion | Out-String).Trimend()
        $PH = (Get-MsixFileInformation -Path "$SourceFile" -Property PublisherHash | Out-String).Trimend()
        $IN = (Get-MsixFileInformation -Path "$SourceFile" -Property IdentityName | Out-String).Trimend()

        # Throw if the specified source file is not an upgrade to the existing app.
        if ($IV -le $app.IdentityVersion) {
            Throw "This application version, $IV is not an upgrade to the existing application version, $($app.identityVersion)"
        }

		# Create a new MSI LOB app.
		$mobileAppBody = Get-MSIXAppBody -DisplayName "$DN" -Description "$DE" -Publisher "$PB" -Filename "$FileName" -IdentityVersion "$IV" -IdentityName "$IN" -IdentityPublisherHash "$PH"

        Write-Host
        Write-Host "Creating application in Intune..." -ForegroundColor Yellow
		Send-PatchRequest "mobileApps/$appId" ($mobileAppBody | ConvertTo-Json)

		# Pause before creating new content version.
		Start-Sleep 15

		# Create a new content version.
        Write-Host
        Write-Host "Creating Content Version in the service for the application..." -ForegroundColor Yellow
		$contentVersionUri = "mobileApps/$appId/$LOBType/contentVersions";
		$contentVersion = Send-PostRequest $contentVersionUri "{}";

        # Encrypt file and Get File Information
        Write-Host
        Write-Host "Ecrypting the file '$SourceFile'..." -ForegroundColor Yellow
        $encryptionInfo = Set-FileEncryption $SourceFile $tempFile;
        $Size = (Get-Item "$SourceFile").Length
        $EncrySize = (Get-Item "$tempFile").Length

        Write-Host
        Write-Host "Creating the manifest file used to install the application on the device..." -ForegroundColor Yellow

        # Get Manifest File Info
        [xml]$manifestXML = Get-MSIXManifest -Path $SourceFile

        $manifestXML_Output = $manifestXML.OuterXml.ToString()

        $Bytes = [System.Text.Encoding]::ASCII.GetBytes($manifestXML_Output)
        $EncodedText =[Convert]::ToBase64String($Bytes)

		# Create a new file for the app.
        Write-Host
        Write-Host "Creating a new file entry in Azure for the upload..." -ForegroundColor Yellow
		$contentVersionId = $contentVersion.id;
		$fileBody = Get-AppFileBody "$FileName" $Size $EncrySize "$EncodedText";
		$filesUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files";
		$file = Send-PostRequest $filesUri ($fileBody | ConvertTo-Json);

		# Wait for the service to process the new file request.
        Write-Host
        Write-Host "Waiting for the file entry URI to be created..." -ForegroundColor Yellow
		$fileId = $file.id;
		$fileUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId";
		$file = Wait-FileProcessing $fileUri "AzureStorageUriRequest";

		# Upload the content to Azure Storage.
        Write-Host
        Write-Host "Uploading file to Azure Storage..." -f Yellow

		$sasUri = $file.azureStorageUri;
		Send-FileToAzureStorage $file.azureStorageUri $tempFile;

		# Commit the file.
        Write-Host
        Write-Host "Committing the file into Azure Storage..." -ForegroundColor Yellow
		$commitFileUri = "mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId/commit";
		Send-PostRequest $commitFileUri ($encryptionInfo | ConvertTo-Json);

		# Wait for the service to process the commit file request.
        Write-Host
        Write-Host "Waiting for the service to process the commit file request..." -ForegroundColor Yellow
		$file = Wait-FileProcessing $fileUri "CommitFile";

		# Commit the app.
        Write-Host
        Write-Host "Committing the file into Azure Storage..." -ForegroundColor Yellow
		$commitAppUri = "mobileApps/$appId";
		$commitAppBody = Get-AppCommitBody $contentVersionId $LOBType;
		Send-PatchRequest $commitAppUri ($commitAppBody | ConvertTo-Json);

        Write-Host "Removing Temporary file '$tempFile'..." -f Gray
        Remove-Item -Path "$tempFile" -Force
        Write-Host

        Write-Host "Sleeping for $sleep seconds to allow patch completion..." -f Magenta
        Start-Sleep $sleep
        Write-Host
	}

    catch
    {
		Write-Host "";
		Write-Host -ForegroundColor Red "Aborting with exception: $($_.Exception.ToString())";
    }

}
####################################################

$baseUrl = "https://graph.microsoft.com/beta/deviceAppManagement/"
$logRequestUris = $true;
$logHeaders = $false;
$logContent = $true;
$sleep = 30
