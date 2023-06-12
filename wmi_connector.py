# File: wmi_connector.py
#
# Copyright (c) 2016-2023 Splunk Inc.
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
import re

import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

import wmi_client_wrapper as wmi
from wmi_consts import *
from wmi_executer import WMIEXEC


class WmiConnector(BaseConnector):

    # Actions supported by this script
    ACTION_ID_GET_PROCESSES = "get_processes"
    ACTION_ID_GET_SERVICES = "get_services"
    ACTION_ID_GET_RUNNING_SERVICES = "get_running_services"
    ACTION_ID_GET_USERS = "get_users"
    ACTION_ID_RUN_QUERY = "run_query"
    ACTION_ID_GET_SYSINFO = "get_sysinfo"
    ACTION_ID_EXECUTE_PROGRAM = "execute_program"

    def __init__(self):

        # Call the BaseConnectors init first
        super(WmiConnector, self).__init__()

    def _get_error_message_from_exception(self, e):
        """
        Get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = None
        error_msg = ERR_MSG_UNAVAILABLE

        self.error_print("Error occurred.", dump_object=e)

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except Exception as e:
            self.error_print(
                "Error occurred while fetching exception information. Details: {}".format(str(e)))

        if not error_code:
            error_text = "Error Message: {}".format(error_msg)
        else:
            error_text = "Error Code: {}. Error Message: {}".format(
                error_code, error_msg)

        return error_text

    def _modify_exception_message(self, e):

        mod_msg = re.sub('%.* ', '%<password> ',
                         self._get_error_message_from_exception(e))

        self.debug_print("Modified Exception Message:", mod_msg)

        return mod_msg

    def _run_query(self, query, wmic, action_result):

        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        try:
            ret_data = wmic.query(query)
        except Exception as e:
            action_result.set_status(
                phantom.APP_ERROR, WMI_ERR_QUERY_EXECUTION_FAILED)
            action_result.append_to_message(self._modify_exception_message(e))
            return None

        self.debug_print("query_results", ret_data)

        if not ret_data:
            action_result.set_status(
                phantom.APP_ERROR, "Data retrieved was empty")
            return None

        if not isinstance(ret_data, list):
            action_result.set_status(
                phantom.APP_ERROR, "Invalid Data received")
            return None

        action_result.set_status(phantom.APP_SUCCESS)

        # We still need to validate that the data we sent out is sane
        return ret_data

    def _get_sysinfo(self, wmic, action_result):

        cumulative_data = {}

        query = "select * from Win32_ComputerSystem"
        ret_data = self._run_query(query, wmic, action_result)

        if phantom.is_fail(action_result.get_status()):
            return action_result.get_status()

        cumulative_data[WMI_JSON_SYSTEM_DETAILS] = ret_data[0]

        query = "select * from Win32_OperatingSystem"
        ret_data = self._run_query(query, wmic, action_result)

        if phantom.is_fail(action_result.get_status()):
            return action_result.get_status()

        cumulative_data[WMI_JSON_OS_DETAILS] = ret_data[0]

        query = "select * from Win32_BootConfiguration"
        ret_data = self._run_query(query, wmic, action_result)

        if phantom.is_fail(action_result.get_status()):
            return action_result.get_status()

        cumulative_data[WMI_JSON_BOOT_CONFIG_DETAILS] = ret_data[0]

        action_result.add_data(cumulative_data)

        # Create summary
        data = action_result.get_data()

        data = data[0]

        summary = {}

        try:
            summary[WMI_JSON_DNSHOSTNAME] = data[WMI_JSON_SYSTEM_DETAILS].get(
                'DNSHostName', '')
        except:
            pass

        try:
            summary[WMI_JSON_PHYSICAL_MEM] = data[WMI_JSON_SYSTEM_DETAILS]['TotalPhysicalMemory']
        except:
            pass

        try:
            summary[WMI_JSON_WORKGROUP] = data[WMI_JSON_SYSTEM_DETAILS]['Workgroup']
        except:
            pass

        try:
            summary[WMI_JSON_DOMAIN] = data[WMI_JSON_SYSTEM_DETAILS]['Domain']
        except:
            pass

        try:
            summary[WMI_JSON_VERSION] = '{0} [{1}] {2} {3}'.format(
                data[WMI_JSON_OS_DETAILS]['Caption'],
                data[WMI_JSON_OS_DETAILS]['Version'],
                data[WMI_JSON_OS_DETAILS].get('OSArchitecture', 'Unknown'),
                data[WMI_JSON_OS_DETAILS]['CSDVersion'])
        except:
            pass

        action_result.update_summary(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_processes(self, wmic, action_result):

        query = "select * from Win32_Process"

        ret_data = self._run_query(query, wmic, action_result)

        if phantom.is_success(action_result.get_status()) and len(ret_data):
            action_result.update_summary(
                {WMI_JSON_TOTAL_PROCESSES: len(ret_data)})
            for curr_process in ret_data:
                action_result.add_data(curr_process)

        return action_result.get_status()

    def _get_services(self, wmic, action, action_result):

        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        query = "select * from Win32_Service"

        if action == self.ACTION_ID_GET_RUNNING_SERVICES:
            query = "select * from Win32_Service where State = 'Running'"

        ret_data = self._run_query(query, wmic, action_result)
        self.debug_print("query_results", ret_data)

        if phantom.is_success(action_result.get_status()) and len(ret_data):
            action_result.update_summary(
                {WMI_JSON_TOTAL_SERVICES: len(ret_data)})
            total_running = 0
            for curr_service in ret_data:
                action_result.add_data(curr_service)
                if curr_service.get('State', 'Unknown') == 'Running':
                    total_running += 1
            action_result.update_summary(
                {WMI_JSON_RUNNING_SERVICES: total_running})
        else:
            action_result.update_summary({WMI_JSON_TOTAL_SERVICES: 0})

        return action_result.get_status()

    def _get_users(self, wmic, action_result):

        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        query = "select * from Win32_Account where SIDType = 1"

        ret_data = self._run_query(query, wmic, action_result)
        self.debug_print("query_results", ret_data)

        if phantom.is_success(action_result.get_status()) and len(ret_data):
            action_result.update_summary({WMI_JSON_TOTAL_USERS: len(ret_data)})
            total_disabled = 0
            for curr_user in ret_data:
                action_result.add_data(curr_user)
                if curr_user.get('Disabled'):
                    total_disabled += 1
            action_result.update_summary(
                {WMI_JSON_DISABLED_USERS: total_disabled})

        return action_result.get_status()

    def _execute_program(self, param, username, password, ip_address):
        commands = param['command'].split(',')
        shell_type = param['shell_type']
        share = param['share']
        hashes = param.get('hashes', None)
        aesKey = param.get('aesKey', None)
        k = param.get('k', False)
        nooutput = param.get('nooutput', False)
        silentcommand = param.get('silentcommand', False)

        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        shell_type = shell_type.lower()
        if shell_type not in ["cmd", "powershell"]:
            return action_result.set_status(phantom.APP_ERROR, "please enter a valid value for shell type")
        stdout_arr = []
        try:
            command = None

            for command in commands:
                executer = WMIEXEC(command=command.strip(), username=username, password=password, hashes=hashes, aesKey=aesKey, 
                                   share=share, noOutput=nooutput, doKerberos=k, shell_type=shell_type)
                executer.run(ip_address, silentcommand)
                stdout_arr.append(executer.shell._RemoteShell__outputBuffer)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR,
                                            f'{"Error occurred while executing program, Error: "}{error_message} for command {command}')

        for output, command in zip(stdout_arr, commands):
            action_result.add_data(f"---- Command: {command} \n {output}")

        return action_result.set_status(phantom.APP_SUCCESS, 'Program executed successfully')

    def _test_connectivity(self, wmic, action_result):

        self.save_progress("Connecting to server")

        query = "select * from Win32_ComputerSystem"

        self.save_progress("Fetching System Details")

        _ = self._run_query(query, wmic, action_result)

        if phantom.is_fail(action_result.get_status()):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """
        Function that handles all the actions.

        :param param: A dictionary which contains information about the actions to be executed
        :return: Status success/failure
        """

        # First get the config
        config = self.get_config()

        user = config[phantom.APP_JSON_USERNAME]
        passw = config[phantom.APP_JSON_PASSWORD]

        # Get the action
        action = self.get_action_identifier()

        curr_machine = config[phantom.APP_JSON_SERVER]

        if action == self.ACTION_ID_EXECUTE_PROGRAM:
            return self._execute_program(param, user, passw, curr_machine)

        if action != phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            curr_machine = param[phantom.APP_JSON_IP_HOSTNAME]

        # default to same as default in WmiClientWrapper::__init__()
        namespace = param.get('namespace', '//./root/cimv2')

        action_result = self.add_action_result(ActionResult(dict(param)))
        action_result.update_param(
            {phantom.APP_JSON_IP_HOSTNAME: curr_machine})
        wmic = None

        self.save_progress(
            phantom.APP_PROG_CONNECTING_TO_ELLIPSES, curr_machine)

        force_ntlm_v2 = config.get('force_ntlmv2', False)

        try:
            wmic = wmi.WmiClientWrapper(
                username=user, password=passw, host=curr_machine, namespace=namespace, force_ntlm_v2=force_ntlm_v2)
        except Exception as e:
            self.save_progress(WMI_MSG_CONNECTION_FAILED, machine=curr_machine)
            action_result.set_status(
                phantom.APP_ERROR, WMI_MSG_CONNECTION_FAILED, machine=curr_machine)
            action_result.append_to_message(self._modify_exception_message(e))
            return action_result.get_status()

        if action == self.ACTION_ID_GET_PROCESSES:
            return self._get_processes(wmic, action_result)
        elif action == self.ACTION_ID_GET_SERVICES or action == self.ACTION_ID_GET_RUNNING_SERVICES:
            return self._get_services(wmic, action, action_result)
        elif action == self.ACTION_ID_GET_USERS:
            return self._get_users(wmic, action_result)
        elif action == self.ACTION_ID_GET_SYSINFO:
            return self._get_sysinfo(wmic, action_result)
        elif action == self.ACTION_ID_RUN_QUERY:
            query = param[WMI_JSON_QUERY]
            action_result.update_param({WMI_JSON_QUERY: query})
            query_results = self._run_query(query, wmic, action_result)
            if phantom.is_success(action_result.get_status()):
                action_result.add_data(query_results)
                return action_result.set_status(phantom.APP_SUCCESS, WMI_SUCC_QUERY_EXECUTED)
            return action_result.get_status()
        elif action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            return self._test_connectivity(wmic, action_result)

        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import json
    import sys

    import pudb

    pudb.set_trace()

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = WmiConnector()
        connector.print_progress_message = True
        result = connector._handle_action(json.dumps(in_json), None)

        print(result)

    sys.exit(0)
