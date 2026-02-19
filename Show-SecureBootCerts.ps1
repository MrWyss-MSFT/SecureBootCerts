<#
.SYNOPSIS
    Displays Secure Boot certificate and configuration information for Windows devices.

.DESCRIPTION
    This script retrieves and displays comprehensive Secure Boot information including:
    - Platform Key (PK), Key Exchange Key (KEK), and Signature Database (DB/DBX) certificates
    - The signature (intermediate) of the boot manager (bootmgfw.efi)
    - Secure Boot servicing status and available updates
    - UEFI CA 2023 update information
    - Security Version Number (SVN) data from DBX
    - Firmware details (manufacturer, version, release date)
    - Recent TPM-WMI event log entries related to Secure Boot updates

.EXAMPLE
    .\Show-SecureBootCerts.ps1
    
    Displays all Secure Boot certificate and configuration information.

.EXAMPLE
    .\Show-SecureBootCerts.ps1 | Select-Object KEK
    
    Displays only the Key Exchange Key (KEK) certificates.

.EXAMPLE
    .\Show-SecureBootCerts.ps1 | Select-Object PK, KEK, DB
    
    Displays the Platform Key, Key Exchange Key, and Signature Database certificates.

.EXAMPLE
    .\Show-SecureBootCerts.ps1 | Select-Object PCA2011inDBX, AvailableUpdatesFlags
    
    Shows whether PCA 2011 is revoked and what Secure Boot updates are available.

.NOTES
    Requires administrator privileges.

.LINK
    https://github.com/MrWyss-MSFT/SecureBootCerts
#>

#Requires -RunAsAdministrator

#region Functions
function Get-UEFISecureBootCerts {
<#
.SYNOPSIS
    Gets details about the UEFI Secure Boot-related variables.
 
.DESCRIPTION
    Gets details about the UEFI Secure Boot-related variables (db, dbx, kek, pk).
 
.PARAMETER Variable
    The UEFI variable to retrieve (defaults to db)
 
.EXAMPLE
    Get-UEFISecureBootCerts
 
.EXAMPLE
    Get-UEFISecureBootCerts -db
 
.EXAMPLE
    Get-UEFISecureBootCerts -dbx
 
.LINK
    https://oofhours.com/2021/01/19/uefi-secure-boot-who-controls-what-can-run/
 
#Requires -Version 2.0
#>        
    [cmdletbinding()]
    Param (
        [Parameter()]
        [String]$Variable = "db"
    )
    BEGIN {
        $EFI_CERT_X509_GUID = [guid]"a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
        $EFI_CERT_SHA256_GUID = [guid]"c1c41626-504c-4092-aca9-41f936934328"
    }
    PROCESS {
        $db = (Get-SecureBootUEFI -Name $variable).Bytes

        $o = 0

        while ($o -lt $db.Length)
        {
            $guidBytes = $db[$o..($o + 15)]
            [Guid] $guid = [Byte[]]$guidBytes
            $signatureListSize = [BitConverter]::ToUInt32($db, $o + 16)
            $signatureHeaderSize = [BitConverter]::ToUInt32($db, $o + 20)
            $signatureSize = [BitConverter]::ToUInt32($db, $o + 24)
            $signatureCount = ($signatureListSize - 28) / $signatureSize 
            # Write-Host "GUID: $guid"
            # Write-Host "SignatureListSize: $signatureListSize"
            # Write-Host "SignatureHeaderSize: $signatureHeaderSize"
            # Write-Host "SignatureSize: $signatureSize"
            # Write-Host "SignatureCount: $signatureCount"

            $so = $o + 28
            1..$signatureCount | % {

                $ownerBytes = $db[$so..($so+15)]
                [Guid] $signatureOwner = [Byte[]]$ownerBytes
                # Write-Host "SignatureOwner: $signatureOwner"

                if ($guid -eq $EFI_CERT_X509_GUID) {
                    $certBytes = $db[($so+16)..($so+16+$signatureSize-1)]
                    if ($PSEdition -eq "Core") {
                        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate]::new([Byte[]]$certBytes)
                    } else {
                        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                        $cert.Import([Byte[]]$certBytes)
                    }
                    [PSCustomObject] @{
                        SignatureOwner = $signatureOwner
                        SignatureSubject = $cert.Subject
                        Signature = $cert
                        SignatureType = $guid
                    }
                }
                elseif ($guid -eq $EFI_CERT_SHA256_GUID) {
                    $sha256hash = ([Byte[]] $db[($so+16)..($so+48-1)] | % {$_.ToString('X2')} ) -join ''
                    [PSCustomObject] @{
                        SignatureOwner = $signatureOwner
                        Signature = $sha256Hash
                        SignatureType = $guid
                    }
                }
                else {
                    Write-Warning "Unable to decode EFI signature type: $guid"
                }

                $so = $so + $signatureSize
            }

            $o = $o + $signatureListSize
        }

    }
}

Function Get-UEFIBootManagerSignature {
    <#
    .SYNOPSIS
        Retrieves the digital signature certificate chain from the bootmgfw.efi file on the EFI partition.
    
    .DESCRIPTION
        This function mounts the EFI partition, copies the bootmgfw.efi file, and retrieves
        the complete certificate chain used to sign the boot manager.
    
    .PARAMETER EFIDriveLetter
        The drive letter to use for mounting the EFI partition. Default is 'S'.
    
    .EXAMPLE
        Get-UEFIBootManagerSignature
        
        Retrieves the certificate chain for bootmgfw.efi.
    
    .EXAMPLE
        Get-UEFIBootManagerSignature -EFIDriveLetter 'Z'
        
        Mounts the EFI partition to Z: drive and retrieves the certificate chain.
    
    .EXAMPLE
        $sig = Get-UEFIBootManagerSignature
        $sig.CertificateChain | Format-Table Subject, NotBefore, NotAfter
        
        Displays all certificates in the chain.
    
    .OUTPUTS
        PSCustomObject with the following properties:
        - SignerCertificate: The signer certificate subject name
        - CertificateChain: Array of all certificates in the chain with full details
        - FilePath: The path to the bootmgfw.efi file on the EFI partition
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidatePattern('^[A-Z]$')]
        [string]$EFIDriveLetter = 'S'
    )
    
    $efiMountPath = "${EFIDriveLetter}:"
    $efiBootFile = "$efiMountPath\EFI\Microsoft\Boot\bootmgfw.efi"
    $tempCopyPath = "$env:TEMP\bootmgfw_signature_check.efi"
    $mountedByScript = $false
    
    try {
        # Check if EFI partition is already mounted
        if (-not (Test-Path $efiMountPath)) {
            Write-Verbose "Mounting EFI partition to $efiMountPath..."
            mountvol $efiMountPath /s
            $mountedByScript = $true
            Start-Sleep -Milliseconds 500  # Give the system time to mount
        }
        
        # Verify the bootmgfw.efi file exists
        if (-not (Test-Path $efiBootFile)) {
            throw "Boot manager file not found at $efiBootFile"
        }
        
        # Copy the file to a temp location for signature verification
        Write-Verbose "Copying bootmgfw.efi to temporary location..."
        Copy-Item -Path $efiBootFile -Destination $tempCopyPath -Force
        
        # Get the embedded digital signature (not catalog signature)
        Write-Verbose "Reading embedded digital signature..."
        
        # Load the file as X509Certificate2 to get embedded signature
        try {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($tempCopyPath)
            $signature = [PSCustomObject]@{
                SignerCertificate = $cert
                Status = 'Valid'
            }
        }
        catch {
            throw "Unable to read embedded signature from bootmgfw.efi: $_"
        }
        
        # Extract the certificate chain
        $certChain = @()
        
        if ($signature.SignerCertificate) {
            # Get the full certificate chain
            $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            $chain.Build($signature.SignerCertificate) | Out-Null
            
            $order = 0
            foreach ($element in $chain.ChainElements) {
                $cert = $element.Certificate
                $certInfo = [PSCustomObject]@{
                    Order = $order
                    Subject = $cert.Subject
                    Issuer = $cert.Issuer
                    Thumbprint = $cert.Thumbprint
                    NotBefore = $cert.NotBefore
                    NotAfter = $cert.NotAfter
                }
                $certChain += $certInfo
                $order++
            }
        }
        
        return [PSCustomObject]@{
            SignerCertificate = $signature.SignerCertificate.Subject
            CertificateChain = $certChain
            FilePath = $efiBootFile
        }
    }
    catch {
        Write-Error "Error reading boot manager signature: $_"
        return [PSCustomObject]@{
            SignerCertificate = $null
            CertificateChain = @()
            FilePath = $efiBootFile
        }
    }
    finally {
        # Clean up temp file
        if (Test-Path $tempCopyPath) {
            Remove-Item -Path $tempCopyPath -Force -ErrorAction SilentlyContinue
        }
        
        # Unmount EFI partition if we mounted it
        if ($mountedByScript) {
            Write-Verbose "Unmounting EFI partition from $efiMountPath..."
            mountvol $efiMountPath /d
        }
    }
}

Function Parse-SvnData {
    # Parses the SVN data from a byte array or hex string.
    # https://github.com/microsoft/secureboot_objects/blob/b884b605ec686433531511fbc2c8510e59799aaa/PreSignedObjects/DBX/HashesJsonSchema.json#L283
    param (
        [Parameter(Mandatory=$true)]
        $Data
    )

    # Convert hex string to byte array if needed (PowerShell 5 compatible)
    if ($Data -is [string]) {
        $hexString = $Data
        $Data = [byte[]]@(
            for ($i = 0; $i -lt $hexString.Length; $i += 2) {
                [Convert]::ToByte($hexString.Substring($i, 2), 16)
            }
        )
    }

    if ($null -eq $Data -or $Data.Length -lt 32) {
        Write-Error "Data must be at least 32 bytes long."
        return
    }
   
    # Known GUIDs
    # https://github.com/microsoft/secureboot_objects/pull/164#issue-2847603173
    # https://github.com/pbatard/rufus/issues/2244#issuecomment-2243661539
    $knownGuids = @{
        "9d132b61-59d5-4388-ab1c-185c3cb2eb92" = "bootmgr"
        "e8f82e9d-e127-4158-a488-4c18abe2f284" = "cdboot*.efi"
        "c999cac2-7ffe-496f-8127-9e2a8a535976" = "wdsmgfw.efi"
    }

    $version = $Data[0]

    # Extract GUID (little endian)
    $guid = New-Object Guid (
        [BitConverter]::ToUInt32($Data, 1),
        [BitConverter]::ToUInt16($Data, 5),
        [BitConverter]::ToUInt16($Data, 7),
        $Data[9], $Data[10], $Data[11], $Data[12], $Data[13], $Data[14], $Data[15], $Data[16]
    )
    $guidStr = $guid.ToString().ToLower()
   
    # Map to known application names
    if ($knownGuids.ContainsKey($guidStr)) {
        $applicationName = $knownGuids[$guidStr]
    }
    else {
        $applicationName = "Unknown"
    }

    # Extract SVN (4 bytes as UInt32)
    $svnValue = [BitConverter]::ToUInt32($Data, 17)
    $minor = $svnValue -band 0xFFFF
    $major = ($svnValue -shr 16) -band 0xFFFF
    #$reservedHex = ($Data[21..31] | ForEach-Object { $_.ToString("X2") }) -join ' '

    [PSCustomObject]@{
        Version         = $version
        ApplicationGUID = $guid
        ApplicationName = $applicationName
        SVN_Major       = $major
        SVN_Minor       = $minor
        #ReservedBytesHex = $reservedHex
    }
}
#endregion

# Get Secure Boot Certificates
$CertPK = Get-UEFISecureBootCerts -Variable pk
$CertKEK = Get-UEFISecureBootCerts -Variable kek
$CertDB = Get-UEFISecureBootCerts -Variable db
$CertDBX = Get-UEFISecureBootCerts -Variable dbx

# Get the boot manager signature subject of the intermediate certificate
$BootManagerSignature = ((Get-UEFIBootManagerSignature).CertificateChain | where Order -eq 1).Subject

# Check if PCA 2011 is in DBX
$PCA2011inDBX = ($CertDBX | Where-Object SignatureSubject -like "*Microsoft Windows Production PCA 2011*").Count -gt 0

# Get Secure Boot Information from Registry
# Read https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d#bkmk_registry_keys
$SecureBoot = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -ErrorAction SilentlyContinue) # Old location
$SecureBootServicing = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -ErrorAction SilentlyContinue)
$SecureBootServicingDeviceAttributes = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -ErrorAction SilentlyContinue)

# SecureBoot Info
$AvailableUpdates = if ($null -ne $SecureBoot.AvailableUpdates) { $SecureBoot.AvailableUpdates } else { 0 } # Ensure AvailableUpdates is numeric and default to 0 when the registry value is missing/null
$HighConfidenceOptOut = $SecureBoot.HighConfidenceOptOut
$MicrosoftUpdateManagedOptIn = $SecureBoot.MicrosoftUpdateManagedOptIn

# Servicing Info
$UEFICA2023Status = $SecureBootServicing.UEFICA2023Status
$UEFICA2023Error = $SecureBootServicing.UEFICA2023Error
$UEFICA2023ErrorCode = $SecureBootServicing.UEFICA2023ErrorCode
$WindowsUEFICA2023Capable = $SecureBootServicing.WindowsUEFICA2023Capable



# Firmware Info
$FirmwareManufacturer = $SecureBootServicingDeviceAttributes.FirmwareManufacturer
$FirmwareVersion = $SecureBootServicingDeviceAttributes.FirmwareVersion
$FirmwareReleaseDate = $SecureBootServicingDeviceAttributes.FirmwareReleaseDate
$CanAttemptUpdateAfter = $SecureBootServicingDeviceAttributes.CanAttemptUpdateAfter
# Convert CanAttemptUpdateAfter from byte[] to DateTime
if ($CanAttemptUpdateAfter -is [byte[]]) {
    $CanAttemptUpdateAfter = [DateTime]::FromFileTime([BitConverter]::ToInt64($CanAttemptUpdateAfter, 0))
}

<#
0000000000000001 0x0001 → N/A
0000000000000010 0x0002 → N/A
0000000000000100 0x0004 → Apply Microsoft Corporation KEK 2K CA 2023 to KEK
0000000000001000 0x0008 → N/A
0000000000010000 0x0010 → N/A
0000000000100000 0x0020 → N/A
0000000001000000 0x0040 → Apply Windows UEFI CA 2023 certificate to the Secure Boot DB
0000000010000000 0x0080 → Enable the revocation. PCA 2011 Cert to DBX
0000000100000000 0x0100 → apply new boot manager, signed by the Windows UEFI CA 2023, to the boot partition
0000001000000000 0x0200 → SVN update
0000010000000000 0x0400 → N/A
0000100000000000 0x0800 → Apply Microsoft UEFI CA 2023 to the DB
0001000000000000 0x1000 → Apply Microsoft Option ROM CA 2023 to the DB
0010000000000000 0x2000 → N/A
0100000000000000 0x4000 → Apply Microsoft UEFI CA 2023 and Microsoft Option ROM CA 2023 if the DB already has the Microsoft Corporation UEFI CA 2011
1000000000000000 0x8000 → N/A
#>
# Enum

[Flags()] enum AvailableUpdatesFlags {
    None = 0x0000
    Apply_Microsoft_Corporation_KEK_2K_CA_2023 = 0x0004
    Apply_Windows_UEFI_CA_2023 = 0x0040
    Enable_Revocation_PCA_2011_to_DBX = 0x0080
    Apply_New_Boot_Manager_Windows_UEFI_CA_2023 = 0x0100
    SVN_Update = 0x0200
    Apply_Microsoft_UEFI_CA_2023 = 0x0800
    Apply_Microsoft_Option_ROM_CA_2023 = 0x1000
    Apply_Microsoft_UEFI_and_Option_ROM_CA_2023 = 0x4000
}

# WindowsUEFICA2023Capable key https://support.microsoft.com/en-au/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d#:~:text=WindowsUEFICA2023Capable
# Function to convert WindowsUEFICA2023Capable value to descriptive object
function Get-WindowsUEFICA2023CapableInfo {
    param([int]$KeyValue)
    
    $text = switch ($KeyValue) {
        0 { "UEFI CA 2023 Not in DB" }
        1 { "UEFI CA 2023 in DB" }
        2 { "UEFI CA 2023 in DB and Booting with 2023 Boot Manager" }
        default { "Unknown ($KeyValue)" }
    }
    
    [PSCustomObject]@{
        Value = $KeyValue
        Text = $text
    }
}

# Get TPM-WMI event log entries for Secure Boot updates
$LastEvents = Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-TPM-WMI'
    Id           = 1032, 1033, 1034, 1036, 1037, 1043, 1044, 1045, 1795, 1796, 1797, 1798, 1799, 1801, 1808 # <-- https://support.microsoft.com/en-us/topic/secure-boot-db-and-dbx-variable-update-events-37e47cf8-608b-4a87-8175-bdead630eb69
} -MaxEvents 1

# Parse the SVN entries from dbx excluding the bootmgr entry
$SVNs = $CertDBX |
    Where-Object SignatureOwner -eq "9d132b6c-59d5-4388-ab1c-185cfcb2eb92" |
    Select-Object -ExpandProperty Signature |
    ForEach-Object {
        Parse-SvnData -Data $_
    }

[PSCustomObject]@{
    PK = $CertPK.SignatureSubject
    KEK = $CertKEK.SignatureSubject
    DB = $CertDB.SignatureSubject
    BootManagerSignature = $BootManagerSignature
    PCA2011inDBX = $PCA2011inDBX
    SVNs = if ($SVNs) {
        ($SVNs | ForEach-Object { "v$($_.Version) [$($_.ApplicationGUID)]" }) -join ', '
    } else { $null }
    UEFICA2023Status = $UEFICA2023Status
    UEFICA2023Error = $UEFICA2023Error
    UEFICA2023ErrorCode = $UEFICA2023ErrorCode
    WindowsUEFICA2023Capable = Get-WindowsUEFICA2023CapableInfo -KeyValue $WindowsUEFICA2023Capable
    HighConfidenceOptOut = $HighConfidenceOptOut
    MicrosoftUpdateManagedOptIn = $MicrosoftUpdateManagedOptIn
    FirmwareManufacturer = $FirmwareManufacturer
    FirmwareReleaseDate = $FirmwareReleaseDate
    FirmwareVersion = $FirmwareVersion
    CanAttemptUpdateAfter = $CanAttemptUpdateAfter
    AvailableUpdates = $AvailableUpdates
    AvailableUpdatesFlags = [AvailableUpdatesFlags]$AvailableUpdates
    LastEventId = if ($LastEvents) { $LastEvents.Id } else { $null }
    LastEventTime = if ($LastEvents) { $LastEvents.TimeCreated } else { $null }
    LastEventMessage = if ($LastEvents) { $LastEvents.Message } else { $null }
}
