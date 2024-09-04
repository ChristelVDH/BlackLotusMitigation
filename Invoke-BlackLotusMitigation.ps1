#requires -PSEdition Desktop -Version 5.1
[CmdletBinding()]
<#
.SYNOPSIS
invoke BlackLotus mitigation step for step (multiple reboots necessary) and check succes of each step before continuing
.LINK
https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24932
.NOTES
https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d?preview=true
.DESCRIPTION
Authored by ChristelVdH on 4 september 2024
Version 1.2 - 04/09/2024 - added more verbose output inside different steps
tested on Windows 10 and 11, check requirements = ok
possibly not all failures will be intercepted gracefully, use with care in your environment
this script will run until all steps have been succesfully performed
please investigate if device(s) keep failing after at least 6 runs
#>
param(
	[string]$Org,
	[ValidateRange(0,172800)][int]$DelayRebootInSeconds = 0
)

process {
	try { $RebootStatus = Get-ItemPropertyValue -Path $CompanyRegPath -Name Progress } catch { $RebootStatus = "" }
	switch ($RebootStatus) {
		"FirstReboot" { Restart-Me -RegValue "SecondReboot" }
		"SecondReboot" { Set-ItemProperty -Path $CompanyRegPath -Name Progress -Type String -Value "" -Force }
	}
	if (Assert-Revocation) { $ExitCode = $false } #bootloader is successfully patched
	else {
		$WinRE = Invoke-Expression -Command "reagentc /info"
		Write-Verbose -Message "Checking if WinRE is enabled..."
		if ($WinRE -match "Enabled") {
			Write-Verbose -Message "Found WinRE partition, checking if SecureBoot is enabled..."
			if (Confirm-SecureBootUEFI) {
				if (Get-HotFix -Id $KBHotfixes) {
					Write-Verbose -Message "WinRE and SecureBoot are enabled and a current Cumulative Update is present, starting mitigation steps..."
					try { [int]$BLMitigated = Get-ItemPropertyValue -Path "$($SBRegPath)\Servicing" -Name WindowsUEFICA2023Capable }
					catch { [int]$BLMitigated = $false }
					if (-not $BLMitigated) {
						$CertInstalled = ([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023')
						if ($CertInstalled) {
							Write-Verbose -Message "Updating Bootloader with the Windows UEFI CA 2023 certificate..."
							Set-ItemProperty -Path $SBRegPath -Name AvailableUpdates -Type DWord -Value 0x100 -Force
							Restart-Twice -RegValue "FirstReboot"
						}
						else {
							Write-Verbose -Message "Activating 2023 Certificate update step..."
							Set-ItemProperty -Path $SBRegPath -Name AvailableUpdates -Type DWord -Value 0x40 -Force
							Restart-Twice -RegValue "FirstReboot"
						}
					}
					$CertRevoked = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).bytes) -match 'Microsoft Windows Production PCA 2011'
					if (-not $CertRevoked) {
						Write-Verbose -Message "Activating 2011 Certificate Revocation step..."
						Set-ItemProperty -Path $SBRegPath -Name AvailableUpdates -Type DWord -Value 0x80 -Force
						Restart-Twice -RegValue "FirstReboot"
					}
				}
				else {
					Write-Verbose -Message "Missing required current Cumulative Update to invoke mitigation steps"
					try {
						Write-Verbose -Message "Trying to start Intune sync to retrieve applicable update policies..."
						[Windows.Management.MdmSessionManager, Windows.Management, ContentType = WindowsRuntime]
						$session = [Windows.Management.MdmSessionManager]::TryCreateSession()
						$session.StartAsync()
					}
					catch { Write-Error -Message "No MDM agent extension found" }
				}
			}
			else { Write-Warning -Message "Secure boot is NOT enabled!" }
		}
		else { Write-Warning -Message "No WinRE partition found!" }
	}
}

begin {
	if (-not $PSBoundParameters.ContainsKey('Org')) { $Org = 'Org' }
	if (-not $PSBoundParameters.ContainsKey('DelayRebootInSeconds')) { $DelayRebootInSeconds = 28800 }
	$CompanyRegPath = "HKLM:\SOFTWARE\$($Org)\BLMitigation"
	if (-not (Test-Path -Path $CompanyRegPath)) { New-Item -Path $CompanyRegPath -Force }
	$SBRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
	$KBHotfixes = @('KB5034441', 'KB5037019', 'KB5036893', 'KB5040442', 'KB5041585') #add, replace as needed for your organization and time of installation
	$Exitcode = $true #assume failure and keep running script until revocation is asserted successfully
	Write-Warning -Message "Make sure to backup the Bitlocker Recovery key(s): 'manage-bde -protectors -get %systemdrive%'"
	
	Function Restart-Me {
		param ([Parameter(Mandatory)]$RegValue)
		Set-ItemProperty -Path $CompanyRegPath -Name Progress -Type String -Value $RegValue -Force
		switch ($DelayRebootInSeconds){
			0 { shutdown -r -c $RegValue }
			default { shutdown -r -t $DelayRebootInSeconds -c $RegValue }
		}
		exit 1
	}
	Function Assert-Revocation {
		#https://support.microsoft.com/en-us/topic/kb5016061-secure-boot-db-and-dbx-variable-update-events-37e47cf8-608b-4a87-8175-bdead630eb69
		$Revocation = $false
		$TpmIds = @(1032, 1033, 1034, 1036, 1037, 1795, 1796, 1797, 1798, 1799)
		$TpmEvents = Get-WinEvent -ProviderName "Microsoft-Windows-TPM-WMI" | Where-Object { $_.id -in $TpmIds } | Sort-Object TimeCreated
		$TpmEvents | Out-String | Write-Verbose
		switch ($TpmEvents.Id) {
			1032 { 
				"Preventing Bitlocker Recovery mode during BlackLotus mitigation..."
				Suspend-BitLocker -MountPoint C -RebootCount 2
			}
			1033 { $Message += "deferring DBX update..." }
			1034 { $Message += "DBX signature successfully updated" }
			1036 { $Message += "DB certificate successfully updated" }
			1037 { $Message += "PCA 2011 successfully revoked"; $Revocation = $true }
			1795 { $Message += "DBX update went wrong, see event log!!!" }
			1796 { $Message += "DBX update went wrong for unknown reasons!!!" }
			1797 { $Message += "checking if new DB signature is OK before revoking abused certificate..." }
			1798 { $Message += "checking bootmanager certificate before revoking abused signature..." }
			1799 { $Message += "boot manager has been updated to safe version" }
		}
		$Message | Write-Verbose
		return $Revocation
	}
}

end {
	#return 0 or 1, remove -as [int] for True or False
	return $ExitCode -as [int]
}