## SYNOPSIS

Invoke **BlackLotus** mitigation step for step (multiple reboots necessary) and check succes of each step before continuing

## LINKS

[CVE-2023-24932: Secure Boot Security Feature Bypass Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24932)

[KB5025885: How to manage the Windows Boot Manager revocations for Secure Boot changes associated with CVE-2023-24932](https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d?preview=true)

## DESCRIPTION

tested on Windows 10 and 11, check requirements = **OK**  
possibly not all failures will be intercepted gracefully, use with care in your environment

this script will run until all steps have been succesfully performed  
please investigate if device(s) keep failing after at least 6 runs

## PARAMS

- **Org** can be used for the name of your organization (default = **Org**) to use in the registry path that holds script execution progress
- **DelayRebootInSeconds** is the number of seconds (default = 28800 seconds or 8 hours) before a reboot is triggered with notification to the logged on user
- **EnforceReboot** triggers an immediate reboot with a message to the logged on user

## AUTHOR

Authored by ChristelVdH on 4 September 2024

## VERSION

Version 1.2 - 04/09/2024 - added more verbose output inside different steps
