#Requires -Version 7.0
#Requires -RunAsAdministrator
#Requires -Modules UEFIv2

Import-Module -Name UEFIv2

#region Functions
Function Parse-SvnData {
    # Parses the SVN data from a byte array.
    # https://github.com/microsoft/secureboot_objects/blob/b884b605ec686433531511fbc2c8510e59799aaa/PreSignedObjects/DBX/HashesJsonSchema.json#L283
    param (
        [byte[]]$Data
    )

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

$CertPK = Get-UEFISecureBootCerts -Variable pk
$CertKEK = Get-UEFISecureBootCerts -Variable kek
$CertDB = Get-UEFISecureBootCerts -Variable db
$CertDBX = Get-UEFISecureBootCerts -Variable dbx
$MWPPCA2011inDBX = ($CertDBX | Where-Object SignatureSubject -eq "Microsoft Windows Production PCA 2011").Count -gt 0


# Read HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates
$AvailableUpdates = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates" -ErrorAction SilentlyContinue).AvailableUpdates
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
    Parse-SvnData -Data ([System.Convert]::FromHexString($_))
}

$Output = [PSCustomObject]@{
    PK                    = $CertPK
    KEK                   = $CertKEK
    DB                    = $CertDB
    MWPPCA2011inDBX       = $MWPPCA2011inDBX
    SVNs                  = $SVNs
    AvailableUpdates      = $AvailableUpdates
    AvailableUpdatesFlags = [AvailableUpdatesFlags]$AvailableUpdates
    LastEvents            = $LastEvents
}
$Output | Select-Object `
    @{n = 'PK'; e = { $_.PK.SignatureSubject } }, `
    @{n = 'KEK'; e = { $_.KEK.SignatureSubject } }, `
    @{n = 'DB'; e = { $_.DB.SignatureSubject } }, `
    MWPPCA2011inDBX, `
    @{n = 'SVNs'; e = {
            if ($_.SVNs) {
                ($_.SVNs | ForEach-Object { "v$($_.Version) [$($_.ApplicationGUID)]" }) -join ', '
            }
        }
    }, `
    @{n = 'AvailableUpdates'; e = { $_.AvailableUpdates } }, `
    @{n = 'AvailableUpdatesFlags'; e = { $_.AvailableUpdatesFlags } }, `
    
    @{n = 'LastEventId'; e = {
            $e = $_.LastEvents
            if ($e) { $e.Id }
        }
    }, `
    @{n = 'LastEventTime'; e = {
            ($_.LastEvents | Select-Object -ExpandProperty TimeCreated)
        }
    }, `
    @{n = 'LastEventMessage'; e = {
            ($_.LastEvents | Select-Object -ExpandProperty Message)
        }
    }






