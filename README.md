[comment]: # "Auto-generated SOAR connector documentation"
# WMI

Publisher: Splunk  
Connector Version: 2\.1\.7  
Product Vendor: Microsoft  
Product Name: Windows Server  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

This App uses the WMI WQL to implement investigative actions that are executed on a Windows endpoint

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
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


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Windows Server asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**server** |  required  | string | Server IP/Hostname
**username** |  required  | string | Administrator username
**password** |  required  | password | Administrator password
**force\_ntlmv2** |  optional  | boolean | Add option to force NTLMv2 \(Used only for WMI\)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[list services](#action-list-services) - Get the list of installed services on the system  
[get system info](#action-get-system-info) - Get information about a system  
[list users](#action-list-users) - List users configured on a system  
[run query](#action-run-query) - Run an arbitrary query using WQL on the system  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list services'
Get the list of installed services on the system

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | Hostname/IP to list services running on | string |  `ip`  `host name` 
**namespace** |  optional  | Namespace | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.namespace | string | 
action\_result\.data\.\*\.AcceptPause | boolean | 
action\_result\.data\.\*\.AcceptStop | boolean | 
action\_result\.data\.\*\.Caption | string | 
action\_result\.data\.\*\.CheckPoint | string | 
action\_result\.data\.\*\.CreationClassName | string | 
action\_result\.data\.\*\.Description | string | 
action\_result\.data\.\*\.DesktopInteract | boolean | 
action\_result\.data\.\*\.DisconnectedSessions | string | 
action\_result\.data\.\*\.DisplayName | string | 
action\_result\.data\.\*\.ErrorControl | string | 
action\_result\.data\.\*\.ExitCode | string | 
action\_result\.data\.\*\.InstallDate | string | 
action\_result\.data\.\*\.Name | string | 
action\_result\.data\.\*\.PathName | string |  `file path`  `file name` 
action\_result\.data\.\*\.ProcessId | string |  `pid` 
action\_result\.data\.\*\.ServiceSpecificExitCode | string | 
action\_result\.data\.\*\.ServiceType | string | 
action\_result\.data\.\*\.StartMode | string | 
action\_result\.data\.\*\.StartName | string | 
action\_result\.data\.\*\.Started | boolean | 
action\_result\.data\.\*\.State | string | 
action\_result\.data\.\*\.Status | string | 
action\_result\.data\.\*\.SystemCreationClassName | string | 
action\_result\.data\.\*\.SystemName | string | 
action\_result\.data\.\*\.TagId | string | 
action\_result\.data\.\*\.TotalSessions | string | 
action\_result\.data\.\*\.WaitHint | string | 
action\_result\.summary\.running\_services | numeric | 
action\_result\.summary\.total\_services | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get system info'
Get information about a system

Type: **investigate**  
Read only: **True**

For information on Namespaces of Windows Management Instrumentation, refer to the 'Namespace Parameter' section in the documentation\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | Hostname/IP address to get info of | string |  `ip`  `host name` 
**namespace** |  optional  | Namespace | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.namespace | string | 
action\_result\.data\.\*\.boot\_config\_details\.BootDirectory | string |  `file path` 
action\_result\.data\.\*\.boot\_config\_details\.Caption | string | 
action\_result\.data\.\*\.boot\_config\_details\.ConfigurationPath | string |  `file path` 
action\_result\.data\.\*\.boot\_config\_details\.Description | string | 
action\_result\.data\.\*\.boot\_config\_details\.LastDrive | string | 
action\_result\.data\.\*\.boot\_config\_details\.Name | string | 
action\_result\.data\.\*\.boot\_config\_details\.ScratchDirectory | string |  `file path` 
action\_result\.data\.\*\.boot\_config\_details\.SettingID | string | 
action\_result\.data\.\*\.boot\_config\_details\.TempDirectory | string |  `file path` 
action\_result\.data\.\*\.os\_details\.BootDevice | string | 
action\_result\.data\.\*\.os\_details\.BuildNumber | string | 
action\_result\.data\.\*\.os\_details\.BuildType | string | 
action\_result\.data\.\*\.os\_details\.CSCreationClassName | string | 
action\_result\.data\.\*\.os\_details\.CSDVersion | string | 
action\_result\.data\.\*\.os\_details\.CSName | string | 
action\_result\.data\.\*\.os\_details\.Caption | string | 
action\_result\.data\.\*\.os\_details\.CodeSet | string | 
action\_result\.data\.\*\.os\_details\.CountryCode | string | 
action\_result\.data\.\*\.os\_details\.CreationClassName | string | 
action\_result\.data\.\*\.os\_details\.CurrentTimeZone | string | 
action\_result\.data\.\*\.os\_details\.DataExecutionPrevention\_32BitApplications | boolean | 
action\_result\.data\.\*\.os\_details\.DataExecutionPrevention\_Available | boolean | 
action\_result\.data\.\*\.os\_details\.DataExecutionPrevention\_Drivers | boolean | 
action\_result\.data\.\*\.os\_details\.DataExecutionPrevention\_SupportPolicy | string | 
action\_result\.data\.\*\.os\_details\.Debug | boolean | 
action\_result\.data\.\*\.os\_details\.Description | string | 
action\_result\.data\.\*\.os\_details\.Distributed | boolean | 
action\_result\.data\.\*\.os\_details\.EncryptionLevel | string | 
action\_result\.data\.\*\.os\_details\.ForegroundApplicationBoost | string | 
action\_result\.data\.\*\.os\_details\.FreePhysicalMemory | string | 
action\_result\.data\.\*\.os\_details\.FreeSpaceInPagingFiles | string | 
action\_result\.data\.\*\.os\_details\.FreeVirtualMemory | string | 
action\_result\.data\.\*\.os\_details\.InstallDate | string | 
action\_result\.data\.\*\.os\_details\.LargeSystemCache | string | 
action\_result\.data\.\*\.os\_details\.LastBootUpTime | string | 
action\_result\.data\.\*\.os\_details\.LocalDateTime | string | 
action\_result\.data\.\*\.os\_details\.Locale | string | 
action\_result\.data\.\*\.os\_details\.MUILanguages | string | 
action\_result\.data\.\*\.os\_details\.Manufacturer | string | 
action\_result\.data\.\*\.os\_details\.MaxNumberOfProcesses | string | 
action\_result\.data\.\*\.os\_details\.MaxProcessMemorySize | string | 
action\_result\.data\.\*\.os\_details\.Name | string | 
action\_result\.data\.\*\.os\_details\.NumberOfLicensedUsers | string | 
action\_result\.data\.\*\.os\_details\.NumberOfProcesses | string | 
action\_result\.data\.\*\.os\_details\.NumberOfUsers | string | 
action\_result\.data\.\*\.os\_details\.OSArchitecture | string | 
action\_result\.data\.\*\.os\_details\.OSLanguage | string | 
action\_result\.data\.\*\.os\_details\.OSProductSuite | string | 
action\_result\.data\.\*\.os\_details\.OSType | string | 
action\_result\.data\.\*\.os\_details\.OperatingSystemSKU | string | 
action\_result\.data\.\*\.os\_details\.Organization | string | 
action\_result\.data\.\*\.os\_details\.OtherTypeDescription | string | 
action\_result\.data\.\*\.os\_details\.PAEEnabled | boolean | 
action\_result\.data\.\*\.os\_details\.PlusProductID | string | 
action\_result\.data\.\*\.os\_details\.PlusVersionNumber | string | 
action\_result\.data\.\*\.os\_details\.Primary | boolean | 
action\_result\.data\.\*\.os\_details\.ProductType | string | 
action\_result\.data\.\*\.os\_details\.RegisteredUser | string | 
action\_result\.data\.\*\.os\_details\.SerialNumber | string | 
action\_result\.data\.\*\.os\_details\.ServicePackMajorVersion | string | 
action\_result\.data\.\*\.os\_details\.ServicePackMinorVersion | string | 
action\_result\.data\.\*\.os\_details\.SizeStoredInPagingFiles | string | 
action\_result\.data\.\*\.os\_details\.Status | string | 
action\_result\.data\.\*\.os\_details\.SuiteMask | string | 
action\_result\.data\.\*\.os\_details\.SystemDevice | string | 
action\_result\.data\.\*\.os\_details\.SystemDirectory | string |  `file path` 
action\_result\.data\.\*\.os\_details\.SystemDrive | string | 
action\_result\.data\.\*\.os\_details\.TotalSwapSpaceSize | string | 
action\_result\.data\.\*\.os\_details\.TotalVirtualMemorySize | string | 
action\_result\.data\.\*\.os\_details\.TotalVisibleMemorySize | string | 
action\_result\.data\.\*\.os\_details\.Version | string | 
action\_result\.data\.\*\.os\_details\.WindowsDirectory | string |  `file path` 
action\_result\.data\.\*\.system\_details\.AdminPasswordStatus | string | 
action\_result\.data\.\*\.system\_details\.AutomaticManagedPagefile | boolean | 
action\_result\.data\.\*\.system\_details\.AutomaticResetBootOption | boolean | 
action\_result\.data\.\*\.system\_details\.AutomaticResetCapability | boolean | 
action\_result\.data\.\*\.system\_details\.BootOptionOnLimit | string | 
action\_result\.data\.\*\.system\_details\.BootOptionOnWatchDog | string | 
action\_result\.data\.\*\.system\_details\.BootROMSupported | boolean | 
action\_result\.data\.\*\.system\_details\.BootupState | string | 
action\_result\.data\.\*\.system\_details\.Caption | string | 
action\_result\.data\.\*\.system\_details\.ChassisBootupState | string | 
action\_result\.data\.\*\.system\_details\.CreationClassName | string | 
action\_result\.data\.\*\.system\_details\.CurrentTimeZone | string | 
action\_result\.data\.\*\.system\_details\.DNSHostName | string |  `host name` 
action\_result\.data\.\*\.system\_details\.DaylightInEffect | boolean | 
action\_result\.data\.\*\.system\_details\.Description | string | 
action\_result\.data\.\*\.system\_details\.Domain | string |  `domain` 
action\_result\.data\.\*\.system\_details\.DomainRole | string |  `domain` 
action\_result\.data\.\*\.system\_details\.EnableDaylightSavingsTime | boolean | 
action\_result\.data\.\*\.system\_details\.FrontPanelResetStatus | string | 
action\_result\.data\.\*\.system\_details\.InfraredSupported | boolean | 
action\_result\.data\.\*\.system\_details\.InitialLoadInfo | string | 
action\_result\.data\.\*\.system\_details\.InstallDate | string | 
action\_result\.data\.\*\.system\_details\.KeyboardPasswordStatus | string | 
action\_result\.data\.\*\.system\_details\.LastLoadInfo | string | 
action\_result\.data\.\*\.system\_details\.Manufacturer | string | 
action\_result\.data\.\*\.system\_details\.Model | string | 
action\_result\.data\.\*\.system\_details\.Name | string | 
action\_result\.data\.\*\.system\_details\.NameFormat | string | 
action\_result\.data\.\*\.system\_details\.NetworkServerModeEnabled | boolean | 
action\_result\.data\.\*\.system\_details\.NumberOfLogicalProcessors | string | 
action\_result\.data\.\*\.system\_details\.NumberOfProcessors | string | 
action\_result\.data\.\*\.system\_details\.OEMLogoBitmap | string | 
action\_result\.data\.\*\.system\_details\.OEMStringArray | string | 
action\_result\.data\.\*\.system\_details\.PCSystemType | string | 
action\_result\.data\.\*\.system\_details\.PartOfDomain | boolean |  `domain` 
action\_result\.data\.\*\.system\_details\.PauseAfterReset | string | 
action\_result\.data\.\*\.system\_details\.PowerManagementCapabilities | string | 
action\_result\.data\.\*\.system\_details\.PowerManagementSupported | boolean | 
action\_result\.data\.\*\.system\_details\.PowerOnPasswordStatus | string | 
action\_result\.data\.\*\.system\_details\.PowerState | string | 
action\_result\.data\.\*\.system\_details\.PowerSupplyState | string | 
action\_result\.data\.\*\.system\_details\.PrimaryOwnerContact | string | 
action\_result\.data\.\*\.system\_details\.PrimaryOwnerName | string | 
action\_result\.data\.\*\.system\_details\.ResetCapability | string | 
action\_result\.data\.\*\.system\_details\.ResetCount | string | 
action\_result\.data\.\*\.system\_details\.ResetLimit | string | 
action\_result\.data\.\*\.system\_details\.Roles | string | 
action\_result\.data\.\*\.system\_details\.Status | string | 
action\_result\.data\.\*\.system\_details\.SupportContactDescription | string | 
action\_result\.data\.\*\.system\_details\.SystemStartupDelay | string | 
action\_result\.data\.\*\.system\_details\.SystemStartupOptions | string | 
action\_result\.data\.\*\.system\_details\.SystemStartupSetting | string | 
action\_result\.data\.\*\.system\_details\.SystemType | string | 
action\_result\.data\.\*\.system\_details\.ThermalState | string | 
action\_result\.data\.\*\.system\_details\.TotalPhysicalMemory | string | 
action\_result\.data\.\*\.system\_details\.UserName | string |  `user name` 
action\_result\.data\.\*\.system\_details\.WakeUpType | string | 
action\_result\.data\.\*\.system\_details\.Workgroup | string | 
action\_result\.summary\.dns\_hostname | string |  `host name` 
action\_result\.summary\.domain | string |  `domain` 
action\_result\.summary\.memory | string | 
action\_result\.summary\.version | string | 
action\_result\.summary\.workgroup | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list users'
List users configured on a system

Type: **investigate**  
Read only: **True**

For information on Namespaces of Windows Management Instrumentation, refer to the 'Namespace Parameter' section in the documentation\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | Hostname/IP address to get users of | string |  `ip`  `host name` 
**namespace** |  optional  | Namespace | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.namespace | string | 
action\_result\.data\.\*\.AccountType | string | 
action\_result\.data\.\*\.Caption | string |  `user name` 
action\_result\.data\.\*\.Description | string | 
action\_result\.data\.\*\.Disabled | boolean | 
action\_result\.data\.\*\.Domain | string |  `domain` 
action\_result\.data\.\*\.FullName | string | 
action\_result\.data\.\*\.InstallDate | string | 
action\_result\.data\.\*\.LocalAccount | boolean | 
action\_result\.data\.\*\.Lockout | boolean | 
action\_result\.data\.\*\.Name | string | 
action\_result\.data\.\*\.PasswordChangeable | boolean | 
action\_result\.data\.\*\.PasswordExpires | boolean | 
action\_result\.data\.\*\.PasswordRequired | boolean | 
action\_result\.data\.\*\.SID | string | 
action\_result\.data\.\*\.SIDType | string | 
action\_result\.data\.\*\.Status | string | 
action\_result\.summary\.disabled\_users | numeric | 
action\_result\.summary\.total\_users | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'run query'
Run an arbitrary query using WQL on the system

Type: **investigate**  
Read only: **True**

For information on Namespaces of Windows Management Instrumentation, refer to the 'Namespace Parameter' section in the documentation\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | Hostname/IP to run WMI query on | string |  `ip`  `host name` 
**query** |  required  | Query \(in WQL format\) | string | 
**namespace** |  optional  | Namespace | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.namespace | string | 
action\_result\.parameter\.query | string | 
action\_result\.data\.\*\.\*\.AccountType | string | 
action\_result\.data\.\*\.\*\.CSCreationClassName | string | 
action\_result\.data\.\*\.\*\.CSName | string | 
action\_result\.data\.\*\.\*\.Caption | string |  `file name` 
action\_result\.data\.\*\.\*\.CommandLine | string |  `file name`  `file path` 
action\_result\.data\.\*\.\*\.CreationClassName | string | 
action\_result\.data\.\*\.\*\.CreationDate | string | 
action\_result\.data\.\*\.\*\.Description | string |  `file name` 
action\_result\.data\.\*\.\*\.Disabled | boolean | 
action\_result\.data\.\*\.\*\.Domain | string |  `domain` 
action\_result\.data\.\*\.\*\.ExecutablePath | string |  `file path`  `file name` 
action\_result\.data\.\*\.\*\.ExecutionState | string | 
action\_result\.data\.\*\.\*\.FullName | string | 
action\_result\.data\.\*\.\*\.GroupComponent | string | 
action\_result\.data\.\*\.\*\.Handle | string | 
action\_result\.data\.\*\.\*\.HandleCount | string | 
action\_result\.data\.\*\.\*\.InstallDate | string | 
action\_result\.data\.\*\.\*\.KernelModeTime | string | 
action\_result\.data\.\*\.\*\.LocalAccount | boolean | 
action\_result\.data\.\*\.\*\.Lockout | boolean | 
action\_result\.data\.\*\.\*\.MaximumWorkingSetSize | string | 
action\_result\.data\.\*\.\*\.MinimumWorkingSetSize | string | 
action\_result\.data\.\*\.\*\.Name | string |  `file name` 
action\_result\.data\.\*\.\*\.OSCreationClassName | string | 
action\_result\.data\.\*\.\*\.OSName | string | 
action\_result\.data\.\*\.\*\.OtherOperationCount | string | 
action\_result\.data\.\*\.\*\.OtherTransferCount | string | 
action\_result\.data\.\*\.\*\.PageFaults | string | 
action\_result\.data\.\*\.\*\.PageFileUsage | string | 
action\_result\.data\.\*\.\*\.ParentProcessId | string |  `pid` 
action\_result\.data\.\*\.\*\.PartComponent | string | 
action\_result\.data\.\*\.\*\.PasswordChangeable | boolean | 
action\_result\.data\.\*\.\*\.PasswordExpires | boolean | 
action\_result\.data\.\*\.\*\.PasswordRequired | boolean | 
action\_result\.data\.\*\.\*\.PeakPageFileUsage | string | 
action\_result\.data\.\*\.\*\.PeakVirtualSize | string | 
action\_result\.data\.\*\.\*\.PeakWorkingSetSize | string | 
action\_result\.data\.\*\.\*\.Priority | string | 
action\_result\.data\.\*\.\*\.PrivatePageCount | string | 
action\_result\.data\.\*\.\*\.ProcessId | string |  `pid` 
action\_result\.data\.\*\.\*\.QuotaNonPagedPoolUsage | string | 
action\_result\.data\.\*\.\*\.QuotaPagedPoolUsage | string | 
action\_result\.data\.\*\.\*\.QuotaPeakNonPagedPoolUsage | string | 
action\_result\.data\.\*\.\*\.QuotaPeakPagedPoolUsage | string | 
action\_result\.data\.\*\.\*\.ReadOperationCount | string | 
action\_result\.data\.\*\.\*\.ReadTransferCount | string | 
action\_result\.data\.\*\.\*\.SID | string | 
action\_result\.data\.\*\.\*\.SIDType | string | 
action\_result\.data\.\*\.\*\.SessionId | string | 
action\_result\.data\.\*\.\*\.Status | string | 
action\_result\.data\.\*\.\*\.TerminationDate | string | 
action\_result\.data\.\*\.\*\.ThreadCount | string | 
action\_result\.data\.\*\.\*\.UserModeTime | string | 
action\_result\.data\.\*\.\*\.VirtualSize | string | 
action\_result\.data\.\*\.\*\.WindowsVersion | string | 
action\_result\.data\.\*\.\*\.WorkingSetSize | string | 
action\_result\.data\.\*\.\*\.WriteOperationCount | string | 
action\_result\.data\.\*\.\*\.WriteTransferCount | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 