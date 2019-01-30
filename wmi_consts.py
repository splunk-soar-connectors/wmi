# File: wmi_consts.py
# Copyright (c) 2016-2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
#
# --

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
WMI_ERR_QUERY_EXECUTION_FAILED = "WMI query failed."
WMI_ERR_QUERY_EXECUTION_FAILED += "\nPlease make sure remote WMI access is enabled on the target machine."
WMI_ERR_QUERY_EXECUTION_FAILED += "\nAny firewall if present is configured to allow remote WMI communication"
WMI_SUCC_SYS_INFO_QUERIED = "System info queried"

# Progress messages format string
WMI_MSG_CONNECTION_FAILED = "WMI connection to {machine} failed"

# Progress strings constants, define them first and then use them in the call to send_progress
CONN_PY_PROG_SENDING_QUERY = "Executing WMI query"
