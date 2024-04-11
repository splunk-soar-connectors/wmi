# File: wmi_consts.py
#
# Copyright (c) 2016-2024 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Json keys specific to wmi app's input parameters/config and the output result
WMI_JSON_QUERY = "query"
WMI_JSON_TOTAL_SERVICES = "total_services"
WMI_JSON_RUNNING_SERVICES = "running_services"
WMI_JSON_TOTAL_PROCESSES = "total_processes"
WMI_JSON_TOTAL_USERS = "total_users"
WMI_JSON_DISABLED_USERS = "disabled_users"
WMI_JSON_SYSTEM_DETAILS = "system_details"
WMI_JSON_OS_DETAILS = "os_details"
WMI_JSON_BOOT_CONFIG_DETAILS = "boot_config_details"
WMI_JSON_DNSHOSTNAME = "dns_hostname"
WMI_JSON_PHYSICAL_MEM = "memory"
WMI_JSON_WORKGROUP = "workgroup"
WMI_JSON_DOMAIN = "domain"
WMI_JSON_VERSION = "version"

# Status messages for wmi app
WMI_SUCC_QUERY_EXECUTED = "WMI Query executed"
WMI_ERROR_QUERY_EXECUTION_FAILED = "WMI query failed."
WMI_ERROR_QUERY_EXECUTION_FAILED += "\nPlease make sure remote WMI access is enabled on the target machine."
WMI_ERROR_QUERY_EXECUTION_FAILED += "\nAny firewall if present is configured to allow remote WMI communication"
WMI_SUCC_SYS_INFO_QUERIED = "System info queried"

# Progress messages format string
WMI_MSG_CONNECTION_FAILED = "WMI connection to {machine} failed"

# Progress strings constants, define them first and then use them in the call to send_progress
CONN_PY_PROG_SENDING_QUERY = "Executing WMI query"

# Constants relating to '_get_error_message_from_exception'
WMI_ERROR_CODE_MSG = "Error code unavailable"
WMI_ERROR_MSG_UNAVAILABLE = "Error msg unavailable. Please check the asset configuration and|or action parameters"
WMI_PARSE_ERROR_MSG = "Unable to parse the error msg. Please check the asset configuration and|or action parameters"
