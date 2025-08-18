# WMI

Publisher: Splunk <br>
Connector Version: 2.1.8 <br>
Product Vendor: Microsoft <br>
Product Name: Windows Server <br>
Minimum Product Version: 6.3.0

This App uses the WMI WQL to implement investigative actions that are executed on a Windows endpoint

Windows Management Instrumentation (WMI) ports need to be opened up on the endpoint for the app to
run WMI commands remotely. Depending upon your setup, this configuration can be part of a Group
Policy Object (GPO) or carried out individually on the endpoint.

This app does not support proxies, and it will ignore any proxy settings.

## wmi-client-wrapper

This app makes use of the Python wmi-client-wrapper module, which is licensed under the BSD License,
Copyright (c) 2013

## wmi-client-wrapper-py3

This app makes use of the Python wmi-client-wrapper-py3 module, which is licensed under the BSD
License, Copyright (c) 2018

### Configuration variables

This table lists the configuration variables required to operate WMI. These variables are specified when configuring a Windows Server asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**server** | required | string | Server IP/Hostname |
**username** | required | string | Administrator username |
**password** | required | password | Administrator password |
**force_ntlmv2** | optional | boolean | Add option to force NTLMv2 (Used only for WMI) |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity <br>
[list services](#action-list-services) - Get the list of installed services on the system <br>
[get system info](#action-get-system-info) - Get information about a system <br>
[list users](#action-list-users) - List users configured on a system <br>
[run query](#action-run-query) - Run an arbitrary query using WQL on the system

## action: 'test connectivity'

Validate the asset configuration for connectivity

Type: **test** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'list services'

Get the list of installed services on the system

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** | required | Hostname/IP to list services running on | string | `ip` `host name` |
**namespace** | optional | Namespace | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.ip_hostname | string | `ip` `host name` | 10.1.17.42 |
action_result.parameter.namespace | string | | |
action_result.data.\*.AcceptPause | boolean | | False True |
action_result.data.\*.AcceptStop | boolean | | False True |
action_result.data.\*.Caption | string | | Active Directory Web Services |
action_result.data.\*.CheckPoint | string | | 0 |
action_result.data.\*.CreationClassName | string | | Win32_Service |
action_result.data.\*.Description | string | | This service provides a Web Service interface to instances of the directory service (AD DS and AD LDS) that are running locally on this server. If this service is stopped or disabled, client applications, such as Active Directory PowerShell, will not be able to access or manage any directory service instances that are running locally on this server. |
action_result.data.\*.DesktopInteract | boolean | | False True |
action_result.data.\*.DisconnectedSessions | string | | 1 |
action_result.data.\*.DisplayName | string | | Active Directory Web Services |
action_result.data.\*.ErrorControl | string | | Normal |
action_result.data.\*.ExitCode | string | | 0 |
action_result.data.\*.InstallDate | string | | |
action_result.data.\*.Name | string | | ADWS |
action_result.data.\*.PathName | string | `file path` `file name` | C:\\Windows\\ADWS\\Microsoft.ActiveDirectory.WebServices.exe |
action_result.data.\*.ProcessId | string | `pid` | 1328 |
action_result.data.\*.ServiceSpecificExitCode | string | | 0 |
action_result.data.\*.ServiceType | string | | Own Process |
action_result.data.\*.StartMode | string | | Auto |
action_result.data.\*.StartName | string | | LocalSystem |
action_result.data.\*.Started | boolean | | False True |
action_result.data.\*.State | string | | Running |
action_result.data.\*.Status | string | | OK |
action_result.data.\*.SystemCreationClassName | string | | Win32_ComputerSystem |
action_result.data.\*.SystemName | string | | DC1 |
action_result.data.\*.TagId | string | | 0 |
action_result.data.\*.TotalSessions | string | | 4 |
action_result.data.\*.WaitHint | string | | 0 |
action_result.summary.running_services | numeric | | 69 |
action_result.summary.total_services | numeric | | 150 |
action_result.message | string | | Running services: 69, Total services: 150 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get system info'

Get information about a system

Type: **investigate** <br>
Read only: **True**

For information on Namespaces of Windows Management Instrumentation, refer to the 'Namespace Parameter' section in the documentation.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** | required | Hostname/IP address to get info of | string | `ip` `host name` |
**namespace** | optional | Namespace | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.ip_hostname | string | `ip` `host name` | 10.1.17.42 |
action_result.parameter.namespace | string | | |
action_result.data.\*.boot_config_details.BootDirectory | string | `file path` | C:\\Windows |
action_result.data.\*.boot_config_details.Caption | string | | \\Device\\Harddisk0\\Partition1 |
action_result.data.\*.boot_config_details.ConfigurationPath | string | `file path` | C:\\Windows |
action_result.data.\*.boot_config_details.Description | string | | \\Device\\Harddisk0\\Partition1 |
action_result.data.\*.boot_config_details.LastDrive | string | | D: |
action_result.data.\*.boot_config_details.Name | string | | BootConfiguration |
action_result.data.\*.boot_config_details.ScratchDirectory | string | `file path` | C:\\Windows\\system32\\config\\systemprofile\\AppData\\Local\\Temp |
action_result.data.\*.boot_config_details.SettingID | string | | |
action_result.data.\*.boot_config_details.TempDirectory | string | `file path` | C:\\Windows\\system32\\config\\systemprofile\\AppData\\Local\\Temp |
action_result.data.\*.os_details.BootDevice | string | | \\Device\\HarddiskVolume1 |
action_result.data.\*.os_details.BuildNumber | string | | 7601 |
action_result.data.\*.os_details.BuildType | string | | Multiprocessor Free |
action_result.data.\*.os_details.CSCreationClassName | string | | Win32_ComputerSystem |
action_result.data.\*.os_details.CSDVersion | string | | Service Pack 1 |
action_result.data.\*.os_details.CSName | string | | DC1 |
action_result.data.\*.os_details.Caption | string | | Microsoft Windows Server 2008 R2 Enterprise |
action_result.data.\*.os_details.CodeSet | string | | 1252 |
action_result.data.\*.os_details.CountryCode | string | | 1 |
action_result.data.\*.os_details.CreationClassName | string | | Win32_OperatingSystem |
action_result.data.\*.os_details.CurrentTimeZone | string | | -420 |
action_result.data.\*.os_details.DataExecutionPrevention_32BitApplications | boolean | | False True |
action_result.data.\*.os_details.DataExecutionPrevention_Available | boolean | | False True |
action_result.data.\*.os_details.DataExecutionPrevention_Drivers | boolean | | False True |
action_result.data.\*.os_details.DataExecutionPrevention_SupportPolicy | string | | 3 |
action_result.data.\*.os_details.Debug | boolean | | False True |
action_result.data.\*.os_details.Description | string | | Active Directory Server 1 |
action_result.data.\*.os_details.Distributed | boolean | | False True |
action_result.data.\*.os_details.EncryptionLevel | string | | 256 |
action_result.data.\*.os_details.ForegroundApplicationBoost | string | | 2 |
action_result.data.\*.os_details.FreePhysicalMemory | string | | 2091584 |
action_result.data.\*.os_details.FreeSpaceInPagingFiles | string | | 4176236 |
action_result.data.\*.os_details.FreeVirtualMemory | string | | 6127192 |
action_result.data.\*.os_details.InstallDate | string | | 20140817185509.000000-420 |
action_result.data.\*.os_details.LargeSystemCache | string | | 0 |
action_result.data.\*.os_details.LastBootUpTime | string | | 20180913031837.282679-420 |
action_result.data.\*.os_details.LocalDateTime | string | | 20180926081041.684000-420 |
action_result.data.\*.os_details.Locale | string | | 0409 |
action_result.data.\*.os_details.MUILanguages | string | | en-US |
action_result.data.\*.os_details.Manufacturer | string | | Microsoft Corporation |
action_result.data.\*.os_details.MaxNumberOfProcesses | string | | 4294967295 |
action_result.data.\*.os_details.MaxProcessMemorySize | string | | 8589934464 |
action_result.data.\*.os_details.Name | string | | Microsoft Windows Server 2008 R2 Enterprise |C:\\Windows|\\Device\\Harddisk0\\Partition2 |
action_result.data.\*.os_details.NumberOfLicensedUsers | string | | 0 |
action_result.data.\*.os_details.NumberOfProcesses | string | | 92 |
action_result.data.\*.os_details.NumberOfUsers | string | | 5 |
action_result.data.\*.os_details.OSArchitecture | string | | 64-bit |
action_result.data.\*.os_details.OSLanguage | string | | 1033 |
action_result.data.\*.os_details.OSProductSuite | string | | 274 |
action_result.data.\*.os_details.OSType | string | | 18 |
action_result.data.\*.os_details.OperatingSystemSKU | string | | 10 |
action_result.data.\*.os_details.Organization | string | | |
action_result.data.\*.os_details.OtherTypeDescription | string | | |
action_result.data.\*.os_details.PAEEnabled | boolean | | False True |
action_result.data.\*.os_details.PlusProductID | string | | |
action_result.data.\*.os_details.PlusVersionNumber | string | | |
action_result.data.\*.os_details.Primary | boolean | | False True |
action_result.data.\*.os_details.ProductType | string | | 2 |
action_result.data.\*.os_details.RegisteredUser | string | | Windows User |
action_result.data.\*.os_details.SerialNumber | string | | 55041-507-8256601-84196 |
action_result.data.\*.os_details.ServicePackMajorVersion | string | | 1 |
action_result.data.\*.os_details.ServicePackMinorVersion | string | | 0 |
action_result.data.\*.os_details.SizeStoredInPagingFiles | string | | 4193848 |
action_result.data.\*.os_details.Status | string | | OK |
action_result.data.\*.os_details.SuiteMask | string | | 274 |
action_result.data.\*.os_details.SystemDevice | string | | \\Device\\HarddiskVolume2 |
action_result.data.\*.os_details.SystemDirectory | string | `file path` | C:\\Windows\\system32 |
action_result.data.\*.os_details.SystemDrive | string | | C: |
action_result.data.\*.os_details.TotalSwapSpaceSize | string | | 0 |
action_result.data.\*.os_details.TotalVirtualMemorySize | string | | 8385800 |
action_result.data.\*.os_details.TotalVisibleMemorySize | string | | 4193848 |
action_result.data.\*.os_details.Version | string | | 6.1.7601 |
action_result.data.\*.os_details.WindowsDirectory | string | `file path` | C:\\Windows |
action_result.data.\*.system_details.AdminPasswordStatus | string | | 1 |
action_result.data.\*.system_details.AutomaticManagedPagefile | boolean | | False True |
action_result.data.\*.system_details.AutomaticResetBootOption | boolean | | False True |
action_result.data.\*.system_details.AutomaticResetCapability | boolean | | False True |
action_result.data.\*.system_details.BootOptionOnLimit | string | | 3 |
action_result.data.\*.system_details.BootOptionOnWatchDog | string | | 3 |
action_result.data.\*.system_details.BootROMSupported | boolean | | False True |
action_result.data.\*.system_details.BootupState | string | | Normal boot |
action_result.data.\*.system_details.Caption | string | | DC1 |
action_result.data.\*.system_details.ChassisBootupState | string | | 3 |
action_result.data.\*.system_details.CreationClassName | string | | Win32_ComputerSystem |
action_result.data.\*.system_details.CurrentTimeZone | string | | -420 |
action_result.data.\*.system_details.DNSHostName | string | `host name` | DC1 |
action_result.data.\*.system_details.DaylightInEffect | boolean | | False True |
action_result.data.\*.system_details.Description | string | | AT/AT COMPATIBLE |
action_result.data.\*.system_details.Domain | string | `domain` | corp.contoso.com |
action_result.data.\*.system_details.DomainRole | string | `domain` | 5 |
action_result.data.\*.system_details.EnableDaylightSavingsTime | boolean | | False True |
action_result.data.\*.system_details.FrontPanelResetStatus | string | | 3 |
action_result.data.\*.system_details.InfraredSupported | boolean | | False True |
action_result.data.\*.system_details.InitialLoadInfo | string | | NULL |
action_result.data.\*.system_details.InstallDate | string | | |
action_result.data.\*.system_details.KeyboardPasswordStatus | string | | 3 |
action_result.data.\*.system_details.LastLoadInfo | string | | |
action_result.data.\*.system_details.Manufacturer | string | | VMware, Inc. |
action_result.data.\*.system_details.Model | string | | VMware Virtual Platform |
action_result.data.\*.system_details.Name | string | | DC1 |
action_result.data.\*.system_details.NameFormat | string | | |
action_result.data.\*.system_details.NetworkServerModeEnabled | boolean | | False True |
action_result.data.\*.system_details.NumberOfLogicalProcessors | string | | 2 |
action_result.data.\*.system_details.NumberOfProcessors | string | | 1 |
action_result.data.\*.system_details.OEMLogoBitmap | string | | NULL |
action_result.data.\*.system_details.OEMStringArray | string | | [MS_VM_CERT/SHA1/27d66596a61c48dd3dc7216fd715126e33f59ae7],Welcome to the Virtual Machine |
action_result.data.\*.system_details.PCSystemType | string | | 0 |
action_result.data.\*.system_details.PartOfDomain | boolean | `domain` | False True |
action_result.data.\*.system_details.PauseAfterReset | string | | 3932100000 |
action_result.data.\*.system_details.PowerManagementCapabilities | string | | NULL |
action_result.data.\*.system_details.PowerManagementSupported | boolean | | False True |
action_result.data.\*.system_details.PowerOnPasswordStatus | string | | 0 |
action_result.data.\*.system_details.PowerState | string | | 0 |
action_result.data.\*.system_details.PowerSupplyState | string | | 3 |
action_result.data.\*.system_details.PrimaryOwnerContact | string | | |
action_result.data.\*.system_details.PrimaryOwnerName | string | | Windows User |
action_result.data.\*.system_details.ResetCapability | string | | 1 |
action_result.data.\*.system_details.ResetCount | string | | -1 |
action_result.data.\*.system_details.ResetLimit | string | | -1 |
action_result.data.\*.system_details.Roles | string | | LM_Workstation,LM_Server,Primary_Domain_Controller,Timesource,NT,DFS |
action_result.data.\*.system_details.Status | string | | OK |
action_result.data.\*.system_details.SupportContactDescription | string | | NULL |
action_result.data.\*.system_details.SystemStartupDelay | string | | 0 |
action_result.data.\*.system_details.SystemStartupOptions | string | | NULL |
action_result.data.\*.system_details.SystemStartupSetting | string | | 0 |
action_result.data.\*.system_details.SystemType | string | | x64-based PC |
action_result.data.\*.system_details.ThermalState | string | | 3 |
action_result.data.\*.system_details.TotalPhysicalMemory | string | | 4294500352 |
action_result.data.\*.system_details.UserName | string | `user name` | |
action_result.data.\*.system_details.WakeUpType | string | | 6 |
action_result.data.\*.system_details.Workgroup | string | | |
action_result.summary.dns_hostname | string | `host name` | DC1 |
action_result.summary.domain | string | `domain` | corp.contoso.com |
action_result.summary.memory | string | | 4294500352 |
action_result.summary.version | string | | Microsoft Windows Server 2008 R2 Enterprise [6.1.7601] 64-bit Service Pack 1 |
action_result.summary.workgroup | string | | |
action_result.message | string | | Dns hostname: DC1 Domain: corp.contoso.com Version: Microsoft Windows Server 2008 R2 Enterprise [6.1.7601] 64-bit Service Pack 1 Workgroup: None Memory: 4294500352 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'list users'

List users configured on a system

Type: **investigate** <br>
Read only: **True**

For information on Namespaces of Windows Management Instrumentation, refer to the 'Namespace Parameter' section in the documentation.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** | required | Hostname/IP address to get users of | string | `ip` `host name` |
**namespace** | optional | Namespace | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.ip_hostname | string | `ip` `host name` | 10.1.17.42 |
action_result.parameter.namespace | string | | root\\cimv2 |
action_result.data.\*.AccountType | string | | 512 |
action_result.data.\*.Caption | string | `user name` | CORP\\Administrator |
action_result.data.\*.Description | string | | Built-in account for administering the computer/domain |
action_result.data.\*.Disabled | boolean | | False True |
action_result.data.\*.Domain | string | `domain` | CORP |
action_result.data.\*.FullName | string | | The Administrator |
action_result.data.\*.InstallDate | string | | |
action_result.data.\*.LocalAccount | boolean | | False True |
action_result.data.\*.Lockout | boolean | | True False |
action_result.data.\*.Name | string | | Administrator |
action_result.data.\*.PasswordChangeable | boolean | | False True |
action_result.data.\*.PasswordExpires | boolean | | True False |
action_result.data.\*.PasswordRequired | boolean | | False True |
action_result.data.\*.SID | string | | S-1-5-21-3790544232-372029393-2474287633-500 |
action_result.data.\*.SIDType | string | | 1 |
action_result.data.\*.Status | string | | OK |
action_result.summary.disabled_users | numeric | | 9 |
action_result.summary.total_users | numeric | | 57 |
action_result.message | string | | Total users: 57, Disabled users: 9 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'run query'

Run an arbitrary query using WQL on the system

Type: **investigate** <br>
Read only: **True**

For information on Namespaces of Windows Management Instrumentation, refer to the 'Namespace Parameter' section in the documentation.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** | required | Hostname/IP to run WMI query on | string | `ip` `host name` |
**query** | required | Query (in WQL format) | string | |
**namespace** | optional | Namespace | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.ip_hostname | string | `ip` `host name` | 10.1.17.42 |
action_result.parameter.namespace | string | | root/MicrosoftDNS |
action_result.parameter.query | string | | Select * From Win32_Process select * from Win32_Account where SIDType = 1 select * from CIM_Component |
action_result.data.\*.\*.AccountType | string | | 512 |
action_result.data.\*.\*.CSCreationClassName | string | | Win32_ComputerSystem |
action_result.data.\*.\*.CSName | string | | DC1 |
action_result.data.\*.\*.Caption | string | `file name` | System Idle Process CORP\\Administrator |
action_result.data.\*.\*.CommandLine | string | `file name` `file path` | |
action_result.data.\*.\*.CreationClassName | string | | Win32_Process |
action_result.data.\*.\*.CreationDate | string | | 20180913031853.895628-420 |
action_result.data.\*.\*.Description | string | `file name` | System Idle Process Built-in account for administering the computer/domain |
action_result.data.\*.\*.Disabled | boolean | | True False |
action_result.data.\*.\*.Domain | string | `domain` | CORP |
action_result.data.\*.\*.ExecutablePath | string | `file path` `file name` | |
action_result.data.\*.\*.ExecutionState | string | | 0 |
action_result.data.\*.\*.FullName | string | | The Administrator |
action_result.data.\*.\*.GroupComponent | string | | MicrosoftDNS_Domain.DnsServerName="DC1.corp.contoso.com",ContainerName="..RootHints",Name="com." |
action_result.data.\*.\*.Handle | string | | 0 |
action_result.data.\*.\*.HandleCount | string | | 0 |
action_result.data.\*.\*.InstallDate | string | | |
action_result.data.\*.\*.KernelModeTime | string | | 22064786432032 |
action_result.data.\*.\*.LocalAccount | boolean | | True False |
action_result.data.\*.\*.Lockout | boolean | | True False |
action_result.data.\*.\*.MaximumWorkingSetSize | string | | 0 |
action_result.data.\*.\*.MinimumWorkingSetSize | string | | 0 |
action_result.data.\*.\*.Name | string | `file name` | System Idle Process Administrator |
action_result.data.\*.\*.OSCreationClassName | string | | Win32_OperatingSystem |
action_result.data.\*.\*.OSName | string | | Microsoft Windows Server 2008 R2 Enterprise |C:\\Windows|\\Device\\Harddisk0\\Partition2 |
action_result.data.\*.\*.OtherOperationCount | string | | 0 |
action_result.data.\*.\*.OtherTransferCount | string | | 0 |
action_result.data.\*.\*.PageFaults | string | | 1 |
action_result.data.\*.\*.PageFileUsage | string | | 0 |
action_result.data.\*.\*.ParentProcessId | string | `pid` | 0 |
action_result.data.\*.\*.PartComponent | string | | MicrosoftDNS_Domain.DnsServerName="DC1.corp.contoso.com",ContainerName="..RootHints",Name="microsoft.com." |
action_result.data.\*.\*.PasswordChangeable | boolean | | True False |
action_result.data.\*.\*.PasswordExpires | boolean | | True False |
action_result.data.\*.\*.PasswordRequired | boolean | | True False |
action_result.data.\*.\*.PeakPageFileUsage | string | | 0 |
action_result.data.\*.\*.PeakVirtualSize | string | | 0 |
action_result.data.\*.\*.PeakWorkingSetSize | string | | 24 |
action_result.data.\*.\*.Priority | string | | 0 |
action_result.data.\*.\*.PrivatePageCount | string | | 0 |
action_result.data.\*.\*.ProcessId | string | `pid` | 0 |
action_result.data.\*.\*.QuotaNonPagedPoolUsage | string | | 0 |
action_result.data.\*.\*.QuotaPagedPoolUsage | string | | 0 |
action_result.data.\*.\*.QuotaPeakNonPagedPoolUsage | string | | 0 |
action_result.data.\*.\*.QuotaPeakPagedPoolUsage | string | | 0 |
action_result.data.\*.\*.ReadOperationCount | string | | 0 |
action_result.data.\*.\*.ReadTransferCount | string | | 0 |
action_result.data.\*.\*.SID | string | | S-1-5-21-3790544232-372029393-2474287633-500 |
action_result.data.\*.\*.SIDType | string | | 1 |
action_result.data.\*.\*.SessionId | string | | 0 |
action_result.data.\*.\*.Status | string | | OK |
action_result.data.\*.\*.TerminationDate | string | | |
action_result.data.\*.\*.ThreadCount | string | | 2 |
action_result.data.\*.\*.UserModeTime | string | | 0 |
action_result.data.\*.\*.VirtualSize | string | | 0 |
action_result.data.\*.\*.WindowsVersion | string | | 6.1.7601 |
action_result.data.\*.\*.WorkingSetSize | string | | 24576 |
action_result.data.\*.\*.WriteOperationCount | string | | 0 |
action_result.data.\*.\*.WriteTransferCount | string | | 0 |
action_result.summary | string | | |
action_result.message | string | | WMI Query executed |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
