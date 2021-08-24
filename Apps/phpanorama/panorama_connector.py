# File: panorama_connector.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# THIS Connector imports
from panorama_consts import *

import sys
import requests
import xmltodict
import re
import time
from bs4 import UnicodeDammit


class PanoramaConnector(BaseConnector):

    # The actions supported by this connector
    ACTION_ID_BLOCK_URL = "block_url"
    ACTION_ID_UNBLOCK_URL = "unblock_url"
    ACTION_ID_BLOCK_APPLICATION = "block_application"
    ACTION_ID_UNBLOCK_APPLICATION = "unblock_application"
    ACTION_ID_BLOCK_IP = "block_ip"
    ACTION_ID_UNBLOCK_IP = "unblock_ip"
    ACTION_ID_LIST_APPS = "list_apps"
    ACTION_ID_RUN_QUERY = "run_query"

    def __init__(self):

        # Call the BaseConnectors init first
        super(PanoramaConnector, self).__init__()

        self._base_url = None
        self._key = None
        self._version = None
        self._param = None
        self._dev_sys_key = None
        self._device_groups = {}

    def initialize(self):

        config = self.get_config()

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while fetching the Phantom server's Python major version")

        # Base URL
        self._base_url = 'https://{}/api/'.format(config[phantom.APP_JSON_DEVICE])

        self._dev_sys_key = "device-group"

        return phantom.APP_SUCCESS

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.
        :param input_str: Input string to be processed
        :param always_encode: Used if the string needs to be encoded for python 3
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """

        try:
            if input_str and self._python_version == 2:
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_msg = PAN_ERR_MESSAGE
        error_code = PAN_ERR_CODE_MESSAGE
        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = PAN_ERR_CODE_MESSAGE
                    error_msg = e.args[0]
            else:
                error_code = PAN_ERROR_CODE_MESSAGE
                error_msg = PAN_ERROR_MESSAGE
        except:
            error_code = PAN_ERR_CODE_MESSAGE
            error_msg = PAN_ERR_MESSAGE

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = TYPE_ERR_MESSAGE
        except:
            error_msg = PAN_ERR_MESSAGE

        try:
            if error_code in PAN_ERR_CODE_MESSAGE:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
        except:
            self.debug_print("Error occurred while parsing error message")
            error_text = PARSE_ERR_MESSAGE

        return error_text

    def _parse_response_msg(self, response, action_result, response_message):

        msg = response.get('msg')

        if msg is None:
            return

        # parse it as a dictionary
        if isinstance(msg, dict):
            line = msg.get('line')
            if line is None:
                return
            if isinstance(line, list):
                response_message = "{} message: '{}'".format(response_message, ', '.join(line))
                action_result.append_to_message(', '.join(line))
            elif isinstance(line, dict):
                response_message = "{} message: '{}'".format(response_message, line.get('line', ''))
                action_result.append_to_message(line.get('line', ''))
            else:
                response_message = "{} message: '{}'".format(response_message, line)
                action_result.append_to_message(line)
            return

        # parse it as a string
        try:
            if type(msg) == str or type(msg) == unicode:
                response_message = "{} message: '{}'".format(response_message, msg)
                action_result.append_to_message(msg)
        except:
            if type(msg) == str:
                response_message = "{} message: '{}'".format(response_message, msg)
                action_result.append_to_message(msg)
        return response_message

    def _load_pan_version(self, action_result):
        data = {'type': 'version', 'key': self._key}
        status = self._make_rest_call(data, action_result)
        if phantom.is_fail(status):
            return action_result.set_status(
                phantom.APP_ERROR, PAN_ERR_MSG.format("blocking url", action_result.get_message()))

        result_data = action_result.get_data()
        if len(result_data) == 0:
            return phantom.APP_ERROR

        result_data = result_data.pop(0)
        # Version should be in this format '7.1.4', where the 1st digit determines the major version.
        self._version = result_data.get('sw-version')

        if not self._version:
            return phantom.APP_ERROR

        return status

    def _get_pan_major_version(self):
        # version follows this format '7.1.4'.
        return int(self._version.split('.')[0])

    def _parse_response(self, response_dict, action_result):

        # multiple keys could be present even if the response is a failure
        self.debug_print('response_dict', response_dict)

        response = response_dict.get('response')
        response_message = None

        if response is None:
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_REPLY_FORMAT_KEY_MISSING.format(key='response'))

        status = response.get('@status')

        if status is None:
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_REPLY_FORMAT_KEY_MISSING.format(key='response/status'))

        if status != 'success':
            action_result.set_status(phantom.APP_ERROR, PAN_ERR_REPLY_NOT_SUCCESS.format(status=status))
        else:
            response_message = PAN_SUCC_REST_CALL_SUCCEEDED
            action_result.set_status(phantom.APP_SUCCESS)

        code = response.get('@code')
        if code is not None:
            response_message = "{} code: '{}'".format(response_message, code)

        response_message = self._parse_response_msg(response, action_result, response_message)
        self.debug_print(response_message)

        result = response.get('result')

        if result is not None:
            action_result.add_data(result)

        return action_result.get_status()

    def _get_key(self):

        if self._key is not None:
            # key already created for this call
            return phantom.APP_SUCCESS

        config = self.get_config()

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, config[phantom.APP_JSON_DEVICE])
        username = config[phantom.APP_JSON_USERNAME]
        password = config[phantom.APP_JSON_PASSWORD]

        data = {'type': 'keygen', 'user': username, 'password': password}

        try:
            response = requests.post(self._base_url, data=data, verify=config[phantom.APP_JSON_VERIFY])
        except Exception as e:
            self.debug_print(PAN_ERR_DEVICE_CONNECTIVITY, e)
            return self.set_status(phantom.APP_ERROR, PAN_ERR_DEVICE_CONNECTIVITY, self._get_error_message_from_exception(e))

        xml = response.text

        try:
            response_dict = xmltodict.parse(xml)
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, PAN_ERR_UNABLE_TO_PARSE_REPLY, self._get_error_message_from_exception(e))

        response = response_dict.get('response')

        if response is None:
            message = PAN_ERR_REPLY_FORMAT_KEY_MISSING.format(key='response')
            return self.set_status(phantom.APP_ERROR, message)

        status = response.get('@status')

        if status is None:
            message = PAN_ERR_REPLY_FORMAT_KEY_MISSING.format(key='response/status')
            return self.set_status(phantom.APP_ERROR, message)

        if status != 'success':
            message = PAN_ERR_REPLY_NOT_SUCCESS.format(status=status)
            return self.set_status(phantom.APP_ERROR, message)

        result = response.get('result')

        if result is None:
            message = PAN_ERR_REPLY_FORMAT_KEY_MISSING.format(key='response/result')
            return self.set_status(phantom.APP_ERROR, message)

        key = result.get('key')

        if key is None:
            message = PAN_ERR_REPLY_FORMAT_KEY_MISSING.format(key='response/result/key')
            return self.set_status(phantom.APP_ERROR, message)

        self._key = key

        return phantom.APP_SUCCESS

    def _test_connectivity(self, param):

        # Progress
        self.save_progress(PAN_PROG_USING_BASE_URL, base_url=self._base_url)

        status = self._get_key()

        if phantom.is_fail(status):
            self.append_to_message(PAN_ERR_TEST_CONNECTIVITY_FAILED)
            return self.get_status()

        self.save_progress(PAN_SUCC_TEST_CONNECTIVITY_PASSED)

        return self.set_status(phantom.APP_SUCCESS, PAN_SUCC_TEST_CONNECTIVITY_PASSED)

    def _make_rest_call(self, data, action_result):

        self.debug_print("Making rest call")

        config = self.get_config()

        try:
            response = requests.post(self._base_url, data=data, verify=config[phantom.APP_JSON_VERIFY])
        except Exception as e:
            self.debug_print(PAN_ERR_DEVICE_CONNECTIVITY, e)
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_DEVICE_CONNECTIVITY, self._get_error_message_from_exception(e))

        xml = response.text

        action_result.add_debug_data(xml)

        try:
            response_dict = xmltodict.parse(xml)
        except Exception as e:
            self.save_progress(PAN_ERR_UNABLE_TO_PARSE_REPLY)
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_UNABLE_TO_PARSE_REPLY, self._get_error_message_from_exception(e))

        status = self._parse_response(response_dict, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        return action_result.get_status()

    def _add_commit_status(self, job, action_result):

        if job['result'] == 'OK':
            return phantom.APP_SUCCESS

        status_string = ""

        if job['result'] == 'FAIL':

            action_result.set_status(phantom.APP_ERROR)

            try:
                status_string = '{}{}'.format(status_string, '\n'.join(job['details']['line']))
            except Exception as e:
                self.debug_print("Parsing commit status dict, handled exception", self._get_error_message_from_exception(e))
                pass

            try:
                status_string = '\n'.join(job['warnings']['line'])
            except:
                pass

        action_result.append_to_message("\n{0}".format(status_string))

        return phantom.APP_SUCCESS

    def _commit_config(self, action_result):

        self.save_progress("Commiting the config to Panorama")

        data = {'type': 'commit',
                'cmd': '<commit></commit>',
                'key': self._key}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        # Get the job id of the commit call from the result_data, also pop it since we don't need it
        # to be in the action result
        result_data = action_result.get_data()

        if len(result_data) == 0:
            return action_result.get_status()

        result_data = result_data.pop(0)
        job_id = result_data.get('job')

        if not job_id:
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_NO_JOB_ID)

        self.debug_print("commit job id: ", job_id)

        while True:
            data = {'type': 'op',
                    'key': self._key,
                    'cmd': '<show><jobs><id>{job}</id></jobs></show>'.format(job=job_id)}

            status_action_result = ActionResult()

            status = self._make_rest_call(data, status_action_result)

            if phantom.is_fail(status):
                action_result.set_status(phantom.APP_SUCCESS, status_action_result.get_message())
                return action_result.get_status()

            self.debug_print("status", status_action_result)

            # get the result_data and the job status
            result_data = status_action_result.get_data()
            try:
                job = result_data[0]['job']
                if job['status'] == 'FIN':
                    self._add_commit_status(job, action_result)
                    break
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing response from server. {}".format(err))

            # send the % progress
            self.send_progress(PAN_PROG_COMMIT_PROGRESS, progress=job.get('progress'))

            time.sleep(2)

        return action_result.get_status()

    def _get_all_device_groups(self, param, action_result):
        """Get all the device groups configured on the system"""

        device_groups = []

        data = {'type': 'config',
                'action': 'get',
                'key': self._key,
                'xpath': "/config/devices/entry/device-group"}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return (action_result.get_status(), device_groups)

        # Get the data, if the policy existed, we will have some data
        result_data = action_result.get_data()

        if not result_data:
            return (action_result.set_status(phantom.APP_ERROR, "Got empty list for device groups"), device_groups)

        try:
            device_groups = result_data[0]['device-group']['entry']
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, "Unable to parse response for the device group listing"), self._get_error_message_from_exception(e))

        try:
            device_groups = [x['@name'] for x in device_groups]
        except:
            device_groups = [device_groups['@name']]

        # remove the data from action_result
        action_result.set_data_size(0)
        action_result.set_status(phantom.APP_ERROR)

        return (phantom.APP_SUCCESS, device_groups)

    def _get_device_commit_details_string(self, commit_all_device_details):

        try:
            if type(commit_all_device_details) == str or type(commit_all_device_details) == unicode:
                return commit_all_device_details
        except:
            if type(commit_all_device_details) == str:
                return commit_all_device_details

        if type(commit_all_device_details) == dict:
            try:
                return "{0}, warnings: {1}".format('\n'.join(commit_all_device_details['msg']['errors']['line']),
                        '\n'.join(commit_all_device_details['msg']['warnings']['line']))
            except Exception as e:
                self.debug_print("Parsing commit all device details dict, handled exception", self._get_error_message_from_exception(e))
                return "UNKNOWN"

    def _parse_device_group_job_response(self, job, action_result):

        status_string = ''
        device_group_status = phantom.APP_ERROR

        if job['result'] == 'OK':
            device_group_status |= phantom.APP_SUCCESS

        devices = []

        try:
            devices = job['devices']['entry']
        except Exception as e:
            self.debug_print("Parsing commit all message, handled exception", self._get_error_message_from_exception(e))
            devices = []

        if isinstance(devices, dict):
            devices = [devices]

        status_string = '{}<ul>'.format(status_string)
        if not devices:
            status_string = '{}<li>No device status found, possible that no devices configured</li>'.format(status_string)

        for device in devices:
            try:
                if device['result'] != 'FAIL':
                    device_group_status |= phantom.APP_SUCCESS

                device_status = "Device Name: {0}, Result: {1}, Details: {2}".format(device['devicename'], device['result'],
                        self._get_device_commit_details_string(device['details']))
                status_string = "{0}<li>{1}</li>".format(status_string, device_status)
            except Exception as e:
                self.debug_print("Parsing commit all message for a single device, handled exception", self._get_error_message_from_exception(e))

        status_string = '{}</ul>'.format(status_string)

        status_string = "Commit status for device group '{0}':\n{1}".format(job['dgname'], status_string)

        return action_result.set_status(device_group_status, status_string)

    def _parse_device_job_response(self, job, device_ar):

        status = phantom.APP_ERROR
        status_message = ''

        try:
            result = job['result']
        except:
            return device_ar.set_status(phantom.APP_ERROR, "Unable to parse job response")

        if result == 'OK':
            status = phantom.APP_SUCCESS

        try:
            devices = job['devices']['entry']
        except:
            return device_ar.set_status(status, "Job response did not contain device specific information")

        if isinstance(devices, dict):
            devices = [devices]

        try:
            for device in devices:
                status_message = "{0}\nDevice '{1} ({2})'".format(status_message, device['devicename'], device['serial-no'])
                status_message = "{0}\nStatus: {1}".format(status_message, device['status'])

                detail_lines = []
                details = device.get('details')
                try:
                    if isinstance(details, str) or isinstance(details, unicode):
                        detail_lines.append(details)
                except:
                    if isinstance(details, str):
                        detail_lines.append(details)
                else:
                    try:
                        errors = device['details']['msg']['errors']['line']
                        if not isinstance(errors, list):
                            detail_lines.append(errors)
                        else:
                            detail_lines.extend(errors)
                    except:
                        pass

                    try:
                        warnings = device['details']['msg']['warnings']['line']
                        if not isinstance(warnings, list):
                            detail_lines.append(warnings)
                        else:
                            detail_lines.extend(warnings)
                    except:
                        pass

                status_message = "{}\nDetails:".format(status_message)
                for detail_line in detail_lines:
                    status_message = "{0}\n{1}".format(status_message, detail_line)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return device_ar.set_status(phantom.APP_ERROR, "Error occurred while processing response from server. {}".format(err))

        return device_ar.set_status(status, status_message)

    def _commit_device(self, device_group, device, dev_info, device_ar, param):

        device_group = self._handle_py_ver_compat_for_input_str(param[PAN_JSON_DEVICE_GRP])

        self.save_progress("Commiting the config to device '{0}({1})' belonging to device group '{2}'".format(dev_info['hostname'], device, device_group))

        cmd = COMMIT_ALL_DEV_GRP_DEV_CMD.format(device_group=device_group, dev_ser_num=dev_info['serial'])

        data = {'type': 'commit',
                'action': 'all',
                'cmd': cmd,
                'key': self._key}

        commit_dev_ar = ActionResult()

        status = self._make_rest_call(data, commit_dev_ar)

        if phantom.is_fail(status):
            return device_ar.set_status(commit_dev_ar.get_status(), commit_dev_ar.get_message())

        # Get the job id of the commit call from the result_data, also pop it since we don't need it
        # to be in the action result
        result_data = commit_dev_ar.get_data()

        if len(result_data) == 0:
            return device_ar.set_status(commit_dev_ar.get_status(), commit_dev_ar.get_message())

        result_data = result_data.pop(0)
        job_id = result_data.get('job')

        if not job_id:
            return device_ar.set_status(phantom.APP_ERROR, PAN_ERR_NO_JOB_ID)

        self.debug_print("commit job id: ", job_id)

        while True:
            data = {'type': 'op',
                    'key': self._key,
                    'cmd': '<show><jobs><id>{job}</id></jobs></show>'.format(job=job_id)}

            status_action_result = ActionResult()

            status = self._make_rest_call(data, status_action_result)

            if phantom.is_fail(status):
                return device_ar.set_status(phantom.APP_SUCCESS, status_action_result.get_message())

            self.debug_print("status", status_action_result)

            # get the result_data and the job status
            result_data = status_action_result.get_data()
            job = result_data[0].get('job')
            if not job:
                continue
            try:
                if job['status'] == 'FIN':
                    self._parse_device_job_response(job, device_ar)
                    break
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return device_ar.set_status(phantom.APP_ERROR, "Error occurred while processing response from server. {}".format(err))

            # send the % progress
            self.send_progress(PAN_PROG_COMMIT_PROGRESS, progress=job.get('progress'))

            time.sleep(2)

        return device_ar.get_status()

    def _commit_device_group(self, device_group, param, action_result):

        self.save_progress("Commiting the config to the device group '{0}'".format(device_group))

        data = {'type': 'commit',
                'action': 'all',
                'cmd': '<commit-all><shared-policy><device-group><entry name="{0}"/></device-group></shared-policy></commit-all>'.format(device_group),
                'key': self._key}

        rest_call_action_result = ActionResult()

        status = self._make_rest_call(data, rest_call_action_result)

        if phantom.is_fail(status):
            return action_result.set_status(rest_call_action_result.get_status(), rest_call_action_result.get_message())

        # Get the job id of the commit call from the result_data, also pop it since we don't need it
        # to be in the action result
        result_data = rest_call_action_result.get_data()

        if len(result_data) == 0:
            return action_result.set_status(rest_call_action_result.get_status(), rest_call_action_result.get_message())

        result_data = result_data.pop(0)
        job_id = result_data.get('job')

        if not job_id:
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_NO_JOB_ID)

        self.debug_print("commit job id: ", job_id)

        while True:
            data = {'type': 'op',
                    'key': self._key,
                    'cmd': '<show><jobs><id>{job}</id></jobs></show>'.format(job=job_id)}

            status_action_result = ActionResult()

            status = self._make_rest_call(data, status_action_result)

            if phantom.is_fail(status):
                action_result.set_status(phantom.APP_SUCCESS, status_action_result.get_message())
                return action_result.get_status()

            self.debug_print("status", status_action_result)

            # get the result_data and the job status
            result_data = status_action_result.get_data()
            try:
                job = result_data[0]['job']
                if job['status'] == 'FIN':
                    self._parse_device_group_job_response(job, action_result)
                    break
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing response from server. {}".format(err))

            # send the % progress
            self.send_progress(PAN_PROG_COMMIT_PROGRESS, progress=job.get('progress'))

            time.sleep(2)

        return action_result.get_status()

    def _get_addr_name(self, ip):

        # Remove the slash in the ip if present, PAN does not like slash in the names
        rem_slash = lambda x: re.sub(r'(.*)/(.*)', r'\1 mask \2', x)

        name = "{0} {1}".format(rem_slash(ip), PHANTOM_ADDRESS_NAME)

        return name

    def _add_address_entry(self, param, action_result):

        ip_type = None
        name = None
        tag = self.get_container_id()
        block_ip = self._handle_py_ver_compat_for_input_str(param[PAN_JSON_IP])

        # Add the tag to the system
        data = {'type': 'config',
                'action': 'set',
                'key': self._key,
                'xpath': TAG_XPATH.format(config_xpath=self._get_config_xpath(param)),
                'element': TAG_ELEM.format(tag=tag, tag_comment=TAG_CONTAINER_COMMENT, tag_color=TAG_COLOR)}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return (action_result.get_status(), name)

        # Try to figure out the type of ip
        if block_ip.find('/') != -1:
            ip_type = 'ip-netmask'
        elif block_ip.find('-') != -1:
            ip_type = 'ip-range'
        elif phantom.is_ip(block_ip):
            ip_type = 'ip-netmask'
        elif phantom.is_hostname(block_ip):
            ip_type = 'fqdn'
        else:
            return (action_result.set_status(phantom.APP_ERROR, PAN_ERR_INVALID_IP_FORMAT), name)

        name = self._get_addr_name(block_ip)

        address_xpath = IP_ADDR_XPATH.format(config_xpath=self._get_config_xpath(param), ip_addr_name=name)

        data = {'type': 'config',
                'action': 'set',
                'key': self._key,
                'xpath': address_xpath,
                'element': IP_ADDR_ELEM.format(ip_type=ip_type, ip=block_ip, tag=tag)}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return (action_result.get_status(), name)

        return (phantom.APP_SUCCESS, name)

    def _get_security_policy_xpath(self, param, action_result):

        try:
            rules_xpath = '{config_xpath}/{policy_type}/security/rules'.format(config_xpath=self._get_config_xpath(param),
                    policy_type=self._handle_py_ver_compat_for_input_str(param[PAN_JSON_POLICY_TYPE]))
            policy_name = self._handle_py_ver_compat_for_input_str(param[PAN_JSON_POLICY_NAME])
            rules_xpath = "{rules_xpath}/entry[@name='{policy_name}']".format(rules_xpath=rules_xpath, policy_name=policy_name)
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, "Unable to create xpath to the security policies", self._get_error_message_from_exception(e)), None)

        return (phantom.APP_SUCCESS, rules_xpath)

    def _update_security_policy(self, param, sec_policy_type, action_result, name=None, use_source=False):

        sec_policy_name = self._handle_py_ver_compat_for_input_str(param[PAN_JSON_POLICY_NAME])

        self.debug_print("Updating Security Policy", sec_policy_name)

        if (sec_policy_type == SEC_POL_IP_TYPE) and (not use_source):
            element = IP_GRP_SEC_POL_ELEM.format(ip_group_name=name)
        elif (sec_policy_type == SEC_POL_IP_TYPE) and (use_source):
            element = IP_GRP_SEC_POL_ELEM_SRC.format(ip_group_name=name)
        elif sec_policy_type == SEC_POL_APP_TYPE:
            element = APP_GRP_SEC_POL_ELEM.format(app_group_name=name)
        elif sec_policy_type == SEC_POL_URL_TYPE:
            element = URL_PROF_SEC_POL_ELEM.format(url_prof_name=name)
        else:
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_CREATE_UNKNOWN_TYPE_SEC_POL)

        status, rules_xpath = self._get_security_policy_xpath(param, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        data = {'type': 'config',
                'action': 'set',
                'key': self._key,
                'xpath': rules_xpath,
                'element': element}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        return phantom.APP_SUCCESS

    def _unblock_application(self, param):

        status = self._get_key()

        if phantom.is_fail(status):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))

        block_app = self._handle_py_ver_compat_for_input_str(param[PAN_JSON_APPLICATION])

        app_group_name = BLOCK_APP_GROUP_NAME.format(device_group=self._handle_py_ver_compat_for_input_str(param[PAN_JSON_DEVICE_GRP]))
        app_group_name = app_group_name[:MAX_NODE_NAME_LEN].strip()

        xpath = "{0}{1}".format(APP_GRP_XPATH.format(config_xpath=self._get_config_xpath(param), app_group_name=app_group_name),
                DEL_APP_XPATH.format(app_name=block_app))

        data = {'type': 'config',
                'action': 'delete',
                'key': self._key,
                'xpath': xpath}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_MSG.format("unblocking application", action_result.get_message()))

        message = action_result.get_message()
        # Now Commit the config
        self._commit_and_commit_all(param, action_result)

        return action_result.set_status(phantom.APP_SUCCESS, "Response Received: {}".format(message))

    def _block_application(self, param):

        status = self._get_key()

        if phantom.is_fail(status):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))

        if param['policy_type'] not in POLICY_TYPE_VALUE_LIST:
            return action_result.set_status(phantom.APP_ERROR, VALUE_LIST_VALIDATION_MSG.format(POLICY_TYPE_VALUE_LIST, 'policy_type'))

        # Check if policy is present or not
        status, policy_present = self._does_policy_exist(param, action_result)
        action_result.set_data_size(0)
        if phantom.is_fail(status):
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_MSG.format("blocking application", action_result.get_message()))

        if not policy_present:
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_POLICY_NOT_PRESENT_CONFIG_DONT_CREATE)

        self.debug_print("Creating the Application Group")

        block_app = self._handle_py_ver_compat_for_input_str(param[PAN_JSON_APPLICATION])

        app_group_name = BLOCK_APP_GROUP_NAME.format(device_group=self._handle_py_ver_compat_for_input_str(param[PAN_JSON_DEVICE_GRP]))
        app_group_name = app_group_name[:MAX_NODE_NAME_LEN].strip()

        data = {'type': 'config',
                'action': 'set',
                'key': self._key,
                'xpath': APP_GRP_XPATH.format(config_xpath=self._get_config_xpath(param), app_group_name=app_group_name),
                'element': APP_GRP_ELEM.format(app_name=block_app)}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_MSG.format("blocking application", action_result.get_message()))

        message = action_result.get_message()

        # Update the security policy
        status = self._update_security_policy(param, SEC_POL_APP_TYPE, action_result, app_group_name)

        if phantom.is_fail(status):
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_MSG.format("blocking application", action_result.get_message()))

        self._commit_and_commit_all(param, action_result)

        return action_result.set_status(phantom.APP_SUCCESS, "Response Received: {}".format(message))

    def _unblock_url(self, param):

        status = self._get_key()

        if phantom.is_fail(status):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))

        status = self._load_pan_version(action_result)
        if phantom.is_fail(status):
            return action_result.set_status(
                phantom.APP_ERROR, PAN_ERR_MSG.format("blocking url", action_result.get_message()))

        major_version = self._get_pan_major_version()
        if major_version < 9:
            return self._unblock_url_8_and_below(param, action_result)

        return self._unblock_url_9_and_above(param, action_result)

    def _unblock_url_8_and_below(self, param, action_result):
        self.debug_print("Removing the Blocked URL")

        # Add the block url, will create the url profile if not present
        block_url = self._handle_py_ver_compat_for_input_str(param[PAN_JSON_URL])
        url_prof_name = BLOCK_URL_PROF_NAME.format(device_group=self._handle_py_ver_compat_for_input_str(param[PAN_JSON_DEVICE_GRP]))
        url_prof_name = url_prof_name[:MAX_NODE_NAME_LEN].strip()

        xpath = "{0}{1}".format(
            URL_PROF_XPATH.format(config_xpath=self._get_config_xpath(param), url_profile_name=url_prof_name),
            DEL_URL_XPATH.format(url=block_url))

        data = {'type': 'config',
                'action': 'delete',
                'key': self._key,
                'xpath': xpath}

        status = self._make_rest_call(data, action_result)
        if phantom.is_fail(status):
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_MSG.format("unblocking url", action_result.get_message()))

        url_category_del_msg = action_result.get_message()

        # Now Commit the config
        self._commit_and_commit_all(param, action_result)

        return action_result.set_status(phantom.APP_SUCCESS, "Response Received: {}".format(url_category_del_msg))

    def _unblock_url_9_and_above(self, param, action_result):
        self.debug_print("Removing the Blocked URL")

        # Add the block url, will create the url profile if not present
        block_url = self._handle_py_ver_compat_for_input_str(param[PAN_JSON_URL])
        url_prof_name = BLOCK_URL_PROF_NAME.format(
            device_group=self._handle_py_ver_compat_for_input_str(param[PAN_JSON_DEVICE_GRP]))
        url_prof_name = url_prof_name[:MAX_NODE_NAME_LEN].strip()

        xpath = "{0}{1}".format(
            URL_CATEGORY_XPATH.format(config_xpath=self._get_config_xpath(param), url_profile_name=url_prof_name),
            DEL_URL_CATEGORY_XPATH.format(url=block_url))

        data = {'type': 'config',
                'action': 'delete',
                'key': self._key,
                'xpath': xpath}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_MSG.format("unblocking url", action_result.get_message()))

        block_list_del_msg = action_result.get_message()

        # Now Commit the config
        self._commit_and_commit_all(param, action_result)

        return action_result.set_status(phantom.APP_SUCCESS, "Response Received: {}".format(block_list_del_msg))

    def _block_url(self, param):

        status = self._get_key()

        if phantom.is_fail(status):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))

        status = self._load_pan_version(action_result)
        if phantom.is_fail(status):
            return action_result.set_status(
                phantom.APP_ERROR, PAN_ERR_MSG.format("blocking url", action_result.get_message()))

        # Pick BlockUrl handlers based on the major version of Panorama.
        major_version = self._get_pan_major_version()
        if major_version < 9:
            return self._block_url_8_and_below(param, action_result)

        return self._block_url_9_and_above(param, action_result)

    def _block_url_9_and_above(self, param, action_result):
        if param['policy_type'] not in POLICY_TYPE_VALUE_LIST:
            return action_result.set_status(phantom.APP_ERROR, VALUE_LIST_VALIDATION_MSG.format(POLICY_TYPE_VALUE_LIST, 'policy_type'))

        status, policy_present = self._does_policy_exist(param, action_result)
        action_result.set_data_size(0)
        if phantom.is_fail(status):
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_MSG.format("blocking url", action_result.get_message()))

        if not policy_present:
            return action_result.set_status(
                phantom.APP_ERROR, PAN_ERR_POLICY_NOT_PRESENT_CONFIG_DONT_CREATE)

        url_prof_name = BLOCK_URL_PROF_NAME.format(
            device_group=self._handle_py_ver_compat_for_input_str(param[PAN_JSON_DEVICE_GRP]))
        url_prof_name = url_prof_name[:MAX_NODE_NAME_LEN].strip()

        status = self._create_or_update_url_category(param, action_result, url_prof_name)
        if phantom.is_fail(status):
            error_msg = PAN_ERR_MSG.format("blocking url", action_result.get_message())
            return action_result.set_status(phantom.APP_ERROR, error_msg)

        status = self._create_or_update_url_filtering(param, action_result, url_prof_name)
        if phantom.is_fail(status):
            error_msg = PAN_ERR_MSG.format("blocking url", action_result.get_message())
            return action_result.set_status(phantom.APP_ERROR, error_msg)

        # We need to capture the url filter message here before it gets updated below.
        url_filter_message = action_result.get_message()

        # Link the URL filtering profile to the given policy.
        status = self._update_security_policy(param, SEC_POL_URL_TYPE, action_result, url_prof_name)

        if phantom.is_fail(status):
            error_msg = PAN_ERR_MSG.format("blocking url", action_result.get_message())
            return action_result.set_status(phantom.APP_ERROR, error_msg)

        # Now Commit the config
        self._commit_and_commit_all(param, action_result)

        return action_result.set_status(phantom.APP_SUCCESS, "Response Received: {}".format(url_filter_message))

    def _block_url_8_and_below(self, param, action_result):
        if param['policy_type'] not in POLICY_TYPE_VALUE_LIST:
            return action_result.set_status(
                phantom.APP_ERROR, VALUE_LIST_VALIDATION_MSG.format(POLICY_TYPE_VALUE_LIST, 'policy_type'))

        # Check if policy is present or not
        status, policy_present = self._does_policy_exist(param, action_result)
        action_result.set_data_size(0)
        if phantom.is_fail(status):
            return action_result.set_status(
                phantom.APP_ERROR, PAN_ERR_MSG.format("blocking url", action_result.get_message()))

        if not policy_present:
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_POLICY_NOT_PRESENT_CONFIG_DONT_CREATE)

        self.debug_print("Adding the Block URL")
        # Add the block url, will create the url profile if not present
        url_prof_name = BLOCK_URL_PROF_NAME.format(device_group=self._handle_py_ver_compat_for_input_str(param[PAN_JSON_DEVICE_GRP]))
        url_prof_name = url_prof_name[:MAX_NODE_NAME_LEN].strip()

        status = self._create_or_update_url_filtering(param, action_result, url_prof_name)
        if phantom.is_fail(status):
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_MSG.format("blocking url", action_result.get_message()))

        message = action_result.get_message()

        # Create the policy
        status = self._update_security_policy(param, SEC_POL_URL_TYPE, action_result, url_prof_name)

        if phantom.is_fail(status):
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_MSG.format("blocking url", action_result.get_message()))

        # Now Commit the config
        self._commit_and_commit_all(param, action_result)

        return action_result.set_status(phantom.APP_SUCCESS, "Response Received: {}".format(message))

    def _create_or_update_url_category(self, param, action_result, url_prof_name):
        # Add the block url, will create the url profile if not present
        block_url = self._handle_py_ver_compat_for_input_str(param[PAN_JSON_URL])

        xpath = URL_CATEGORY_XPATH.format(config_xpath=self._get_config_xpath(param), url_profile_name=url_prof_name)
        element = URL_CATEGORY_ELEM.format(url=block_url)

        data = {'type': 'config',
                'action': 'set',
                'key': self._key,
                'xpath': xpath,
                'element': element}

        status = self._make_rest_call(data, action_result)

        return status

    def _create_or_update_url_filtering(self, param, action_result, url_prof_name):
        xpath = URL_PROF_XPATH.format(config_xpath=self._get_config_xpath(param), url_profile_name=url_prof_name)

        if self._get_pan_major_version() < 9:
            block_url = self._handle_py_ver_compat_for_input_str(param[PAN_JSON_URL])
            element = URL_PROF_ELEM.format(url=block_url)
        else:
            element = URL_PROF_ELEM_9.format(url_category_name=url_prof_name)

        data = {'type': 'config',
                'action': 'set',
                'key': self._key,
                'xpath': xpath,
                'element': element}

        status = self._make_rest_call(data, action_result)

        return status

    def _get_dgs(self, action_result):

        dgs_ar = ActionResult()

        data = {'type': 'op',
                'cmd': '<show><devicegroups></devicegroups></show>',
                'key': self._key}

        status = self._make_rest_call(data, dgs_ar)

        if phantom.is_fail(status):
            return (action_result.set_status(action_result.get_status(), action_result.get_message()), None)

        dgs = dgs_ar.get_data()

        if not dgs:
            return (action_result.set_status(phantom.APP_ERROR, "Got an empty list of connected devices"), None)

        try:
            dgs = dgs[0]['devicegroups']['entry']
        except Exception as e:
            self.debug_print("Parsing connected devices exception:", e)
            return (action_result.set_status(phantom.APP_ERROR, "Unable to parse connected devices query response"), None)

        if not dgs:
            return (action_result.set_status(phantom.APP_ERROR, "Got an empty list of connected devices"), None)

        ret_dgs = {}
        # Do some cleanup, the response is a xml parsed into json.
        try:
            for curr_dg in dgs:

                # set this dg in the master dictionary of dgs
                name = curr_dg['@name']
                dg = {'devices': {}, '@name': name}
                ret_dgs[name] = dg

                devices = curr_dg.get('devices')

                if not devices:
                    continue

                entry = curr_dg['devices'].get('entry')
                if not entry:
                    continue

                if isinstance(entry, dict):
                    devices = [entry]
                else:
                    # it's a list
                    devices = entry

                # it's a list
                for device in devices:
                    name = device['@name']
                    dg['devices'][name] = device
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return (action_result.set_status(phantom.APP_ERROR, "Error occurred while processing response from server. {}".format(err)), None)

        return (phantom.APP_SUCCESS, ret_dgs)

    def _set_action_result_status(self, dg_status, action_result):

        status = phantom.APP_ERROR
        status_message = ''

        dg_status_value = list(dg_status.items())
        for dg, dg_status in dg_status_value:

            status_message = "{0}Device Group: '{1}'\n".format(status_message, dg)
            devices = dg_status.get('devices')
            if not devices:
                status |= phantom.APP_ERROR
                status_message = '{}No Devices'.format(status_message)
                continue

            devices_value = list(devices.items())
            for device, dev_ar in devices_value:
                status |= dev_ar.get_status()
                status_message = '{0}{1}\n'.format(status_message, dev_ar.get_message())

        return action_result.set_status(status, status_message)

    def _commit_and_commit_all(self, param, action_result):

        # Now Commit the config
        status = self._commit_config(action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        device_group = self._handle_py_ver_compat_for_input_str(param[PAN_JSON_DEVICE_GRP])
        device_groups = [device_group]

        if device_group.lower() == PAN_DEV_GRP_SHARED:
            # get all the device groups
            status, device_groups = self._get_all_device_groups(param, action_result)
            if phantom.is_fail(status):
                return action_result.get_status()

        if not device_groups:
            return action_result.set_status(phantom.APP_ERROR, "Got empty device group list")

        # Reset the action_result object to error
        action_result.set_status(phantom.APP_ERROR)

        dev_groups_ar = []
        for device_group in device_groups:
            dev_grp_ar = ActionResult()
            dev_groups_ar.append(dev_grp_ar)
            self._commit_device_group(device_group, param, dev_grp_ar)

        status = phantom.APP_ERROR
        status_message = ''
        for dev_group_ar in dev_groups_ar:
            status |= dev_group_ar.get_status()
            status_message = '{}{}'.format(status_message, dev_group_ar.get_message())

        action_result.set_status(status, status_message)

        return action_result.get_status()

    def _commit_and_commit_all_per_device(self, param, action_result):

        # Get the list of connected devices
        status, dgs = self._get_dgs(action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        self._device_groups = dgs

        # Now Commit the config
        status = self._commit_config(action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        # Now Commit for each device in the device group
        device_group = self._handle_py_ver_compat_for_input_str(param[PAN_JSON_DEVICE_GRP])
        device_groups = [device_group]

        if device_group.lower() == PAN_DEV_GRP_SHARED:
            # get all the device groups
            status, device_groups = self._get_all_device_groups(param, action_result)
            if phantom.is_fail(status):
                return action_result.get_status()

        if not device_groups:
            return action_result.set_status(phantom.APP_ERROR, "Got empty device group list")

        # Reset the action_result object to error
        action_result.set_status(phantom.APP_ERROR)

        # committing for the device group does not give us proper status strings
        # so the best thing to do is save each device manually
        # get back all the results and show it to the user

        dg_status = {}

        for device_group in device_groups:

            dg_info = dgs.get(device_group)

            if not dg_info:
                dg_status[device_group] = {'status': phantom.APP_ERROR, 'message': 'Device group {0} not found in the response from the device'.format(device_group)}
                continue

            devices = dg_info.get('devices')

            if not devices:
                dg_status[device_group] = {'status': phantom.APP_ERROR, 'message': 'Device group {0} does not contain any devices'.format(device_group)}
                continue

            dg_status[device_group] = curr_dg_status = {'status': phantom.APP_ERROR, 'message': ''}

            curr_dg_status['devices'] = curr_dg_devices = {}

            devices_values = list(devices.items())
            for device, dev_info in devices_values:

                # create a status dictionary
                curr_dg_devices[device] = device_ar = ActionResult()

                if dev_info['connected'].lower() == 'no':
                    device_ar.set_status(phantom.APP_ERROR, "Device '{0} ({1})' ignored since it's not connected to the device group".format(dev_info['hostname'],
                        dev_info['serial']))
                    continue

                # need to commit on this device
                self._commit_device(device_group, device, dev_info, device_ar, param)

        self._set_action_result_status(dg_status, action_result)

        return action_result.get_status()

    def _unblock_ip(self, param):

        status = self._get_key()

        if phantom.is_fail(status):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Create the ip addr name
        unblock_ip = self._handle_py_ver_compat_for_input_str(param[PAN_JSON_IP])

        addr_name = self._get_addr_name(unblock_ip)

        # Check if src or dst
        use_source = param.get(PAN_JSON_SOURCE_ADDRESS, PAN_DEFAULT_SOURCE_ADDRESS)

        if use_source:
            block_ip_grp = BLOCK_IP_GROUP_NAME_SRC.format(device_group=self._handle_py_ver_compat_for_input_str(param[PAN_JSON_DEVICE_GRP]))
        else:
            block_ip_grp = BLOCK_IP_GROUP_NAME.format(device_group=self._handle_py_ver_compat_for_input_str(param[PAN_JSON_DEVICE_GRP]))

        ip_group_name = block_ip_grp
        ip_group_name = ip_group_name[:MAX_NODE_NAME_LEN].strip()

        xpath = "{0}{1}".format(ADDR_GRP_XPATH.format(config_xpath=self._get_config_xpath(param),
            ip_group_name=ip_group_name),
                DEL_ADDR_GRP_XPATH.format(addr_name=addr_name))

        # Remove the address from the phantom address group
        data = {'type': 'config',
                'action': 'delete',
                'key': self._key,
                'xpath': xpath}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_MSG.format("unblocking ip", action_result.get_message()))

        message = action_result.get_message()
        # Now Commit the config
        self._commit_and_commit_all(param, action_result)

        return action_result.set_status(phantom.APP_SUCCESS, "Response Received: {}".format(message))

    def _block_ip(self, param):

        status = self._get_key()

        if phantom.is_fail(status):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))

        if param['policy_type'] not in POLICY_TYPE_VALUE_LIST:
            return action_result.set_status(phantom.APP_ERROR, VALUE_LIST_VALIDATION_MSG.format(POLICY_TYPE_VALUE_LIST, 'policy_type'))

        # Check if policy is present or not
        status, policy_present = self._does_policy_exist(param, action_result)
        action_result.set_data_size(0)
        if phantom.is_fail(status):
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_MSG.format("blocking ip", action_result.get_message()))

        if not policy_present:
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_POLICY_NOT_PRESENT_CONFIG_DONT_CREATE)

        # Next create the ip
        self.debug_print("Adding the IP Group")

        # Check where the IP should go
        use_source = param.get(PAN_JSON_SOURCE_ADDRESS, PAN_DEFAULT_SOURCE_ADDRESS)

        status, addr_name = self._add_address_entry(param, action_result)

        if phantom.is_fail(status):
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_MSG.format("blocking ip", action_result.get_message()))

        if use_source:
            block_ip_grp = BLOCK_IP_GROUP_NAME_SRC.format(device_group=self._handle_py_ver_compat_for_input_str(param[PAN_JSON_DEVICE_GRP]))
        else:
            block_ip_grp = BLOCK_IP_GROUP_NAME.format(device_group=self._handle_py_ver_compat_for_input_str(param[PAN_JSON_DEVICE_GRP]))

        ip_group_name = block_ip_grp
        ip_group_name = ip_group_name[:MAX_NODE_NAME_LEN].strip()

        # Add the address to the phantom address group
        data = {'type': 'config',
                'action': 'set',
                'key': self._key,
                'xpath': ADDR_GRP_XPATH.format(config_xpath=self._get_config_xpath(param), ip_group_name=ip_group_name),
                'element': ADDR_GRP_ELEM.format(addr_name=addr_name)}

        status = self._make_rest_call(data, action_result)

        message = action_result.get_message()

        if phantom.is_fail(status):
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_MSG.format("blocking ip", action_result.get_message()))

        # Update the security policy
        status = self._update_security_policy(param, SEC_POL_IP_TYPE, action_result, ip_group_name, use_source=use_source)

        if phantom.is_fail(status):
            return action_result.get_status()

        self._commit_and_commit_all(param, action_result)

        return action_result.set_status(phantom.APP_SUCCESS, "Response Received: {}".format(message))

    def _run_query(self, param):

        status = self._get_key()

        if phantom.is_fail(status):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))

        query = self._handle_py_ver_compat_for_input_str(param[PAN_JSON_QUERY])
        log_type = param.get(PAN_JSON_LOG_TYPE, 'traffic')

        if log_type not in LOG_TYPE_VALUE_LIST:
            return action_result.set_status(phantom.APP_ERROR, VALUE_LIST_VALIDATION_MSG.format(LOG_TYPE_VALUE_LIST, 'log_type'))

        offset_range = param.get('range', '1-{0}'.format(MAX_QUERY_COUNT))

        spl_range = offset_range.split('-')

        try:
            min_offset = int(spl_range[0].strip())
            max_offset = int(spl_range[1].strip())
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Given range has a bad format: {0}".format(self._get_error_message_from_exception(e)))
        offset_diff = max_offset - min_offset + 1

        if max_offset < min_offset:
            return action_result.set_status(phantom.APP_ERROR, "The given range appears to have a larger number listed first.")

        if min_offset <= 0:
            return action_result.set_status(phantom.APP_ERROR, "The lower end of the range must be greater than zero (indexing starts at 1)")

        if offset_diff > MAX_QUERY_COUNT:
            return action_result.set_status(phantom.APP_ERROR, "The given range is too large. Maxmimum range is {0}.".format(MAX_QUERY_COUNT))

        direction = param.get('direction', 'backward')
        if direction not in DIRECTION_VALUE_LIST:
            return action_result.set_status(phantom.APP_ERROR, VALUE_LIST_VALIDATION_MSG.format(DIRECTION_VALUE_LIST, 'direction'))

        data = {'type': 'log',
                'log-type': log_type,
                'key': self._key,
                'query': query,
                'skip': min_offset - 1,
                'nlogs': offset_diff,
                'dir': direction}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_MSG.format("running query", action_result.get_message()))

        # Get the job id of the query call from the result_data, also pop it since we don't need it
        # to be in the action result
        result_data = action_result.get_data()

        if len(result_data) == 0:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing response. Details: {}".format(action_result.get_message()))

        result_data = result_data.pop(0)
        job_id = result_data.get('job')

        if not job_id:
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_NO_JOB_ID)

        self.debug_print("query job ID: ", job_id)

        data = {'type': 'op',
                'key': self._key,
                'cmd': '<show><query><result><id>{job}</id></result></query></show>'.format(job=job_id)}

        while True:

            status_action_result = ActionResult()

            status = self._make_rest_call(data, status_action_result)

            if phantom.is_fail(status):
                action_result.set_status(phantom.APP_ERROR, "Error occurred while processing response. Details: {}".format(status_action_result.get_message()))
                return action_result.get_status()

            self.debug_print("status", status_action_result)

            # get the result_data and the job status
            result_data = status_action_result.get_data()[0]
            job = result_data.get('job')
            if not job_id:
                continue

            if job.get('status', '') == 'FIN':
                if isinstance(result_data.get('log').get('logs').get('entry'), dict):
                    result_data['log']['logs']['entry'] = [result_data['log']['logs']['entry']]
                action_result.add_data(result_data)
                break

            # send the % progress
            self.send_progress(PAN_PROG_COMMIT_PROGRESS, progress=job.get('progress'))

            time.sleep(2)

        try:
            action_result.set_summary({'num_logs': int(result_data['log']['logs']['@count'])})
        except:
            pass

        return phantom.APP_SUCCESS

    def _get_config_xpath(self, param):

        device_group = self._handle_py_ver_compat_for_input_str(param[PAN_JSON_DEVICE_GRP])

        if device_group.lower() == PAN_DEV_GRP_SHARED:
            return '/config/shared'

        return "/config/devices/entry/device-group/entry[@name='{device_group}']".format(device_group=device_group)

    def _does_policy_exist(self, param, action_result):

        status, rules_xpath = self._get_security_policy_xpath(param, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        data = {'type': 'config',
                'action': 'get',
                'key': self._key,
                'xpath': rules_xpath}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.get_status(), None

        # Get the data, if the policy existed, we will have some data
        result_data = action_result.get_data()

        if not result_data:
            return (phantom.APP_SUCCESS, False)

        total_count = 0

        try:
            total_count = int(result_data[0]['@total-count'])
        except Exception as e:
            self.debug_print("_does_policy_exist handled exception: ", e)
            return (phantom.APP_SUCCESS, False)

        if not total_count:
            return (phantom.APP_SUCCESS, False)

        return (phantom.APP_SUCCESS, True)

    def _list_apps(self, param):

        status = self._get_key()

        if phantom.is_fail(status):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add the address to the phantom address group
        data = {'type': 'config',
                'action': 'get',
                'key': self._key,
                'xpath': APP_LIST_XPATH}

        status = self._make_rest_call(data, action_result)

        if phantom.is_fail(status):
            return action_result.set_status(phantom.APP_ERROR, PAN_ERR_MSG.format("retrieving list of application", action_result.get_message()))

        # Move things around, so that result data is an array of applications
        result_data = action_result.get_data()
        result_data = result_data.pop(0)
        try:
            result_data = result_data['application']['entry']
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing response from server. {}".format(err))

        action_result.update_summary({PAN_JSON_TOTAL_APPLICATIONS: len(result_data)})

        action_result.update_data(result_data)

        return action_result.set_status(phantom.APP_SUCCESS)

    def validate_parameters(self, param):
        """This app does it's own validation
        """
        return phantom.APP_SUCCESS

    def handle_action(self, param):

        result = None
        action = self.get_action_identifier()

        self._param = param

        if action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            result = self._test_connectivity(param)
        elif action == self.ACTION_ID_BLOCK_IP:
            result = self._block_ip(param)
        elif action == self.ACTION_ID_UNBLOCK_IP:
            result = self._unblock_ip(param)
        elif action == self.ACTION_ID_BLOCK_APPLICATION:
            result = self._block_application(param)
        elif action == self.ACTION_ID_UNBLOCK_APPLICATION:
            result = self._unblock_application(param)
        elif action == self.ACTION_ID_BLOCK_URL:
            result = self._block_url(param)
        elif action == self.ACTION_ID_UNBLOCK_URL:
            result = self._unblock_url(param)
        elif action == self.ACTION_ID_LIST_APPS:
            result = self._list_apps(param)
        elif action == self.ACTION_ID_RUN_QUERY:
            result = self._run_query(param)

        return result


if __name__ == '__main__':

    import pudb
    import json

    pudb.set_trace()

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = PanoramaConnector()
        connector.print_progress_message = True
        result = connector._handle_action(json.dumps(in_json), None)

        print(result)

    exit(0)
