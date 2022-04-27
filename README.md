# MSIX_Automation

PowerShell Modules and Examples to assist with MSIX packaging and automation

## Contents

- **MSIX-Automation Module**: This is a PowerShell Module that contains functions
to assist with automating the packaging of existing installers into .msix format.

- **ConvertTo-MSIXExampleAutoDownload.ps1**: This script serves as an example of
how to use the MSIX-Automation module to automatically download the latest version
of a target application and then package it into .msix format. The automated download
is performed by the winget utility.

- **ConvertTo-MSIXExampleProvideInstaller.ps1**: This script serves as an example of
how to use the MSIX-Automation module to provide a file path on the local machine to an
existing installer and then package it into .msix format.

- **MSIX-LOBIntune Module**: This is a PowerShell Module that contains functions
necessary to upload an .msix application to the Intune service or to update an
existing .msix application.

- **Send-LobMsix.ps1**: This is a script serves as an example of how to use the
MSIX-LOBIntune module to import an .msix into Intune as an LOB application.

- **Send-LobMsixUpdate.ps1**: This is a script serves as an example of how to use the
MSIX-LOBIntune module to update an existing MSIX LOB application in Intune.
