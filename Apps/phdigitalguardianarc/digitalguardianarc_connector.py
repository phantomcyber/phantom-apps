# File: digitalguardianarc_connector.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

import sys
import requests
import json
import phantom.app as phantom
from datetime import datetime
from bs4 import BeautifulSoup
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from digitalguardianarc_consts import *
from bs4 import UnicodeDammit


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class DigitalGuardianArcConnector(BaseConnector):
    def __init__(self):

        # Call the BaseConnectors init first

        super(DigitalGuardianArcConnector, self).__init__()
        self._state = None
        self._auth_url = None
        self._arc_url = None
        self._client_id = None
        self._client_secret = None
        self._export_profile = None
        self._api_key = None
        self._client_headers = {}

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})
        return RetVal(action_result.set_status(phantom.APP_ERROR, 'Status Code: {0}. Empty response and no information in the header'.format(response.status_code)), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error

        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            error_text = 'Cannot parse error details {}'.format(err)

        message = "Status Code: {0}. Data from server:{1}".format(
            status_code, self._handle_py_ver_compat_for_input_str(error_text))

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse

        try:
            resp_json = r.json()
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Unable to parse JSON response. {0}'.format(err)), None)

        # Please specify the status codes here

        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json

        message = 'Error from server. Status Code: {0} Data from server: {1}'.format(
                r.status_code, self._handle_py_ver_compat_for_input_str(r.text.replace('{', '{{').replace('}', '}}')))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, response, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails

        try:
            if hasattr(action_result, 'add_debug_data') and (self.get_action_identifier() != 'get-file' or not 200 <= response.status_code < 399):
                action_result.add_debug_data(
                    {'r_status_code': response.status_code})
                action_result.add_debug_data({'r_text': response.text})
                action_result.add_debug_data({'r_headers': response.headers})
            if 'json' in response.headers.get('Content-Type', ''):
                self.save_progress("Action: 'process_json_response'")
                return self._process_json_response(response, action_result)
            if 'html' in response.headers.get('Content-Type', ''):
                self.save_progress("Action: 'process_html_response'")
                return self._process_html_response(response, action_result)
            if not response.text:
                self.save_progress("Action: 'process_empty_response'")
                return self._process_empty_response(response, action_result)
            message = (
                "Can't process response from server. Status Code: {0} Data from server: {1}"
            ).format(response.status_code,
                     self._handle_py_ver_compat_for_input_str(response.text.replace('{', '{{').replace('}', '}}')))
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            exc_tb = sys.exc_info()
            self.save_progress(('exception_line={} {}').format(exc_tb.tb_lineno, err))
            return RetVal(action_result.set_status(phantom.APP_ERROR, ('Error: {}').format(err)), None)

    def _make_rest_call(self, endpoint, action_result, method='get', **kwargs):

        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Invalid method: {0}'.format(method)), resp_json)

        # Create a URL to connect to

        url = "%s/%s" % (self._arc_url.strip("/"), endpoint)
        try:
            self.save_progress("Connecting to URL: {0}".format(url))
            r = request_func(url,
                             verify=config.get('verify_server_cert', False),
                             **kwargs)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Error connecting to server. {0}'.format(err)), resp_json)

        return self._process_response(r, action_result)

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.
        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """

        try:
            if input_str and self._python_version == 2:
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error messages from the exception.
        :param e: Exception object
        :return: error message
        """

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = ERR_CODE_MSG
                    error_msg = e.args[0]
            else:
                error_code = ERR_CODE_MSG
                error_msg = ERR_MSG_UNAVAILABLE
        except:
            error_code = ERR_CODE_MSG
            error_msg = ERR_MSG_UNAVAILABLE

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = TYPE_ERR_MSG
        except:
            error_msg = ERR_MSG_UNAVAILABLE

        try:
            if error_code in ERR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
        except:
            self.debug_print(PARSE_ERR_MSG)
            error_text = PARSE_ERR_MSG

        return error_text

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param

        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress('Connecting to DG ARC')
        ret_val, message = self.requestApiToken()
        if not self._client_headers['Authorization']:
            self.save_progress('Test Connectivity Failed')
            return action_result.get_status()
        else:
            self.save_progress('Test Connectivity Passed')
            return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_on_poll(self, param):
        oldname = ''
        action_result = self.add_action_result(ActionResult(dict(param)))
        response_status, export_list = self.get_export(action_result)
        if phantom.is_fail(response_status):
            self.debug_print('On Poll Failed')
            return action_result.get_status()
        if export_list:
            self.save_progress('Ingesting alarm records')
        else:
            self.save_progress('No export data found')
            return action_result.set_status(phantom.APP_SUCCESS, 'No export data found')
        for entry in export_list:
            try:
                comm = entry['dg_alarm_name'].find(',')
                if comm == -1:
                    comm = 100
                name = ('{alarm_name}-{id}').format(
                    alarm_name=entry['dg_alarm_name'][0:comm],
                    id=entry['dg_guid'])
                if name != oldname:
                    container_id = self.create_container(name, entry)
                    oldname = name
                    if container_id:
                        (artifacts_creation_status,
                         artifacts_creation_msg) = self.create_artifacts(alert=entry, container_id=container_id)
                        if phantom.is_fail(artifacts_creation_status):
                            self.debug_print((
                                'Error while creating artifacts for container with ID {container_id}. {error_msg}'
                            ).format(container_id=container_id, error_msg=artifacts_creation_msg))
                            self._state['first_run'] = False
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                self.debug_print("Error occurred while processing export list response from server. {}".format(err))
        return action_result.set_status(phantom.APP_SUCCESS)

    def get_export(self, action_result):
        self.save_progress('Getting ARC Export data')
        ret_val, message = self.requestApiToken()
        if phantom.is_fail(ret_val):
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)
        full_url = '{0}/export_profiles/{1}/export_and_ack'.format(self._arc_url.strip("/"), self._export_profile)
        try:
            request_response = requests.post(url=full_url,
                                            headers=self._client_headers,
                                            verify=False)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Error connecting to server. {0}'.format(err)), None)

        request_status = request_response.status_code
        if 200 <= request_status <= 299:
            headerField = []
            try:
                jsonText = json.loads(request_response.text)
                if jsonText['total_hits'] == 0:
                    return RetVal(phantom.APP_SUCCESS, None)
                for field in jsonText['fields']:
                    print('name=' + field['name'])
                    headerField.append(field['name'])
                exportdata = []
                for data in jsonText['data']:
                    entryLine = {}
                    headerPosition = 0
                    for dataValue in data:
                        if not dataValue:
                            entryLine[headerField[headerPosition]] = "null"
                        else:
                            entryLine[headerField[headerPosition]] = dataValue
                        headerPosition += 1
                    exportdata.append(entryLine)
                return RetVal(phantom.APP_SUCCESS, exportdata)
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return RetVal(action_result.set_status(phantom.APP_ERROR, 'Unable to parse JSON response. {0}'.format(err)), None)
        else:
            data = self._handle_py_ver_compat_for_input_str(request_response.text.replace('{', '{{').replace('}', '}}'))
            message = 'Error from server. Status Code: {0} Data from server: {1}'.format(request_status, data)
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def create_container(self, name, items):
        container_dict = dict()
        if not items['dg_alert.dg_detection_source'] == 'alert' and items[
                'dg_tags']:
            container_dict['name'] = name
            container_dict['start_time'] = ('{time}Z').format(
                time=datetime.utcfromtimestamp(items['dg_processed_time'] / 1000).isoformat())
            container_dict['source_data_identifier'] = container_dict['name']
            container_dict['severity'] = self.convert_to_phantom_severity(
                items['dg_alarm_sev'])
            container_dict['sensitivity'] = self.convert_to_phantom_sensitivity(items['dg_class.dg_name'])
            custom_fields = {
                'threat type': (items['dg_tags']),
                'activity': (items['dg_utype'])
            }
            container_dict['tags'] = [('{}={}').format(x, custom_fields[x])
                                      for x in custom_fields
                                      if custom_fields[x] is not None]
            container_creation_status, container_creation_msg, container_id = self.save_container(
                container=container_dict)
            if phantom.is_fail(container_creation_status):
                self.save_progress((
                    'Error while creating container for alert {alert_name}. {error_message}'
                ).format(alert_name=items['dg_alarm_name'], error_message=container_creation_msg))
                return None
            else:
                return container_id
        return None

    def create_artifacts(self, alert, container_id):
        """ This function is used to create artifacts in given container using export data.

        :param alert: Data of single export
        :param container_id: ID of container in which we have to create the artifacts
        :return: status(success/failure), message
        """

        artifacts_list = []
        cat = 'alarm'
        # self.save_progress(('action=create_artifacts tenant={} artifact={}').format(self._client_id, json.dumps(alert)))
        operation_mapping = {
            'File': ['Alarm', 'Process', 'Computer', 'User', 'File'],
            'CD/D': ['Alarm', 'Process', 'Computer', 'User', 'File'],
            'Netw':
            ['Alarm', 'Process', 'Computer', 'User', 'File', 'Network'],
            'Send': ['Alarm', 'Process', 'Computer', 'User', 'Email'],
            'Proc': ['Alarm', 'Process', 'Computer', 'User'],
            'Appl': ['Alarm', 'Process', 'Computer', 'User'],
            'ADE ': ['Alarm', 'Process', 'Computer', 'User', 'File'],
            'Prin':
            ['Alarm', 'Process', 'Computer', 'User', 'File', 'Network'],
            'Othe': ['Alarm']
        }
        artifacts_mapping = {
            'Alarm': {
                'Alarm_Name': ('dg_alarm_name', []),
                'Alarm_Severity': ('dg_alarm_sev', []),
                'Threat_Type': ('dg_tags', []),
                'Detection_Name': ('dg_det_name', []),
                'Alert_Category': ('dg_alert.dg_category_name', []),
                'Policy_Name':
                ('dg_alert.dg_alert.dg_alert.dg_policy.dg_name', []),
                'Action_Was_Blocked': ('dg_alert.dg_hc', []),
                'startTime': ('dg_local_timestamp', [])
            },
            'File': {
                'File_Name': ('dg_src_file_name', ['fileName']),
                'File_Size': ('dg_alert.dg_total_size', ['fileSize']),
                'Classification': ('dg_class.dg_name', []),
                'File_Was_Classified': ('dg_hc', []),
                'File_Type': ('dg_src_file_ext', ['fileType']),
                'File_Path': ('dg_alert.uad_sp', ['filePath']),
                'Destination_File_Path': ('dg_alert.uad_dp', ['filePath'])
            },
            'Process': {
                'Process_Name': ('dg_proc_file_name', ['process name']),
                'Parent_Process_Name': ('dg_parent_name', ['app']),
                'Process_Path': ('pi_fp', ['filePath']),
                'Command_Line': ('pi_cmdln', []),
                'MD5': ('dg_md5', ['filehash']),
                'SHA1': ('dg_sha1', ['filehash']),
                'SHA256': ('dg_sha256', ['filehash']),
                'VirusTotal_Status': ('dg_vt_status', [])
            },
            'Email': {
                'Attachment_File_Name':
                ('dg_attachments.dg_src_file_name', ['fileName']),
                'Attachment_Was_Classified': ('dg_attachments.uad_sfc', []),
                'Email_Subject': ('ua_msb', ['email']),
                'Email_Sender': ('ua_ms', ['email']),
                'Email_Recipient': ('dg_recipients.uad_mr', ['email']),
                'Email_Recipient_Domain':
                ('dg_recipients.dg_rec_email_domain', ['domain'])
            },
            'Network': {
                'Destination_Address': ('ua_ra', ['ip', 'ipv4']),
                'Request_URL': ('ua_up', ['url']),
                'Destination_DNS_Domain': ('ua_hn', ['domain']),
                'Remote_Port': ('ua_rp', ['ip'])
            },
            'Computer': {
                'Computer_Name': ('dg_machine_name', ['hostname']),
                'Computer_Type': ('dg_machine_type', []),
                'Source_Host_Name': ('dg_shn', []),
                'Source_IP': ('ua_sa', ['ip', 'ipv4']),
                'Source_Address': ('ua_sa', ['ip', 'ipv4'])
            },
            'User': {
                'User_Name': ('dg_user', ['suser']),
                'NTDomain': ('ua_dn', [])
            }
        }
        specific_alert_mapping = {
            'alarm': {
                'dgarcUID': ('dg_guid', []),
                'dg_process_time': ('dg_process_time', []),
                'Activity': ('dg_utype', []),
                'os_version': ('os_version', []),
                'Policy': ('dg_alert.dg_policy.dg_name', []),
                'Printer_Name': ('uad_pn', []),
                'os': ('os', []),
                'browser': ('browser', []),
                'App_Category': ('appcategory', ['category']),
            }
        }
        for (artifact_name, artifact_keys) in artifacts_mapping.items():
            temp_dict = {}
            cef = {}
            cef_types = {}
            # self.save_progress(('artifact_name={}').format(artifact_name))
            for (artifact_key, artifact_tuple) in artifact_keys.items():
                if alert.get(artifact_tuple[0]):
                    cef[artifact_key] = alert[artifact_tuple[0]]
                    cef_types[artifact_key] = artifact_tuple[1]

            cef['tenant'] = self._client_id
            if cef:
                temp_dict['cef'] = cef
                temp_dict['cef_types'] = cef_types
                temp_dict['name'] = artifact_name
                temp_dict['label'] = artifact_name
                temp_dict['type'] = 'host'
                temp_dict['container_id'] = container_id
                temp_dict['severity'] = self.convert_to_phantom_severity(alert['dg_alarm_sev'])
                temp_dict['source_data_identifier'] = self.create_dict_hash(temp_dict)
                temp_dict['tenant'] = self._client_id

                operation = alert['dg_utype'][:4]
                if operation in operation_mapping.keys():
                    accepted_types = operation_mapping[operation]
                else:
                    accepted_types = operation_mapping['Othe']
                if artifact_name in accepted_types:
                    artifacts_list.append(temp_dict)

        if cat in specific_alert_mapping:
            temp_dict = {}
            cef = {}
            cef_types = {}
            artifact_name = '{} Artifact'.format('Alarm Detail')
            # artifact_name = '{} Artifact'.format(alert.get('dg_alarm_name'))
            for (artifact_key, artifact_tuple) in specific_alert_mapping.get(cat).items():
                if alert.get(artifact_tuple[0]):
                    cef[artifact_key] = alert[artifact_tuple[0]]
                    cef_types[artifact_key] = artifact_tuple[1]
            cef['tenant'] = self._client_id
            if cef:
                temp_dict['cef'] = cef
                temp_dict['cef_types'] = cef_types
                temp_dict['name'] = artifact_name
                temp_dict['label'] = artifact_name
                temp_dict['type'] = 'host'
                temp_dict['container_id'] = container_id
                temp_dict['severity'] = self.convert_to_phantom_severity(alert['dg_alarm_sev'])
                temp_dict['source_data_identifier'] = self.create_dict_hash(temp_dict)
                temp_dict['tenant'] = self._client_id
                artifacts_list.append(temp_dict)

        create_artifact_status, create_artifact_msg, _ = self.save_artifacts(artifacts_list)
        if phantom.is_fail(create_artifact_status):
            return (phantom.APP_ERROR, create_artifact_msg)
        return (phantom.APP_SUCCESS, 'Artifacts created successfully')

    def convert_to_phantom_severity(self, dg_severity):
        if dg_severity == 'Critical':
            phantom_severity = 'High'
        elif dg_severity == 'High':
            phantom_severity = 'Medium'
        else:
            phantom_severity = 'Low'
        return phantom_severity

    # mapping classification name to dlp_high, dlp_restrict,dlp_medium,dlp_low
    def convert_to_phantom_sensitivity(self, dg_classification):
        if dg_classification[-3:] == 'igh':
            phantom_sensitivity = 'red'
        elif dg_classification[-3:] == 'ted':
            phantom_sensitivity = 'red'
        elif dg_classification[-3:] == 'med':
            phantom_sensitivity = 'amber'
        elif dg_classification[-3:] == 'low':
            phantom_sensitivity = 'green'
        else:
            phantom_sensitivity = 'white'
        return phantom_sensitivity

    def create_dict_hash(self, input_dict):
        if not input_dict:
            return
        else:
            try:
                input_dict_str = json.dumps(input_dict, sort_keys=True)
                self.debug_print("Input dictionary is {}".format(self._handle_py_ver_compat_for_input_str(input_dict_str)))
                return
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                self.debug_print("Handled exception in '_create_dict_hash'", err)
                return

    def get_watchlist_id(self, watchListName, action_result):
        ret_val, message = self.requestApiToken()
        if phantom.is_fail(ret_val):
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

        full_url = '{0}/watchlists/'.format(self._arc_url.strip("/"))
        try:
            r = requests.get(url=full_url,
                             headers=self._client_headers,
                             verify=False)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Error connecting to server. {0}'.format(err)), None)
        try:
            jsonText = json.loads(r.text)
            list_id = ''
            if 200 <= r.status_code <= 299:
                jsonText = json.loads(r.text)
                for jText in jsonText:
                    if self._handle_py_ver_compat_for_input_str(jText['display_name']).lower() == watchListName.lower():
                        list_id = jText['name']
                        return RetVal(phantom.APP_SUCCESS, list_id)
                return RetVal(phantom.APP_SUCCESS, list_id)
            else:
                data = self._handle_py_ver_compat_for_input_str(r.text.replace('{', '{{').replace('}', '}}'))
                message = 'Error from server. Status Code: {0} Data from server: {1}'.format(r.status_code, data)
                return RetVal(action_result.set_status(phantom.APP_ERROR, message), list_id)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Unable to process response from the server. {0}'.format(err)), list_id)

    def _check_watchlist_id(self, watch_list_id, watchlist_entry, action_result):
        full_url = '{0}/watchlists/'.format(self._arc_url.strip("/"))
        try:
            r = requests.get(url='{0}{1}/values?limit=100000'.format(full_url, watch_list_id),
                            headers=self._client_headers,
                            verify=False)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Error connecting to server. {0}'.format(err)), None)
        try:
            if 200 <= r.status_code <= 299:
                jsonText = json.loads(r.text)
                entryExists = False
                for jText in jsonText:
                    if self._handle_py_ver_compat_for_input_str(jText['value_name']).lower() == watchlist_entry.lower():
                        entryExists = True
                        return RetVal(phantom.APP_SUCCESS, jText['value_id'])
                if not entryExists:
                    return RetVal(phantom.APP_SUCCESS, '')
            else:
                data = self._handle_py_ver_compat_for_input_str(r.text.replace('{', '{{').replace('}', '}}'))
                message = 'Error from server. Status Code: {0} Data from server: {1}'.format(r.status_code, data)
                return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Unable to process response from the server. {0}'.format(err)), None)

    def get_list_id(self, list_name, list_type, action_result):
        ret_val, message = self.requestApiToken()
        if phantom.is_fail(ret_val):
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)
        full_url = '{0}/lists/{1}'.format(self._arc_url.strip("/"), list_type)
        try:
            r = requests.get(url=full_url,
                            headers=self._client_headers,
                            verify=False)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Error connecting to server. {0}'.format(err)), None)
        try:
            jsonText = json.loads(r.text)
            list_id = ""
            if 200 <= r.status_code <= 299:
                for jText in jsonText:
                    if self._handle_py_ver_compat_for_input_str(jText['name']).lower() == list_name.lower():
                        list_id = jText['id']
                        return RetVal(phantom.APP_SUCCESS, list_id)
                return RetVal(phantom.APP_SUCCESS, None)
            else:
                data = self._handle_py_ver_compat_for_input_str(r.text.replace('{', '{{').replace('}', '}}'))
                message = 'Error from server. Status Code: {0} Data from server: {1}'.format(r.status_code, data)
                return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Unable to process response from the server. {0}'.format(err)), None)

    def _add_watchlist_entry(self, param):
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.debug_print(param)
        watchlist_name = self._handle_py_ver_compat_for_input_str(param['watchlist_name'])
        watchlist_entry = self._handle_py_ver_compat_for_input_str(param['watchlist_entry'])
        msg_string = "{0} to watchlist={1}".format(watchlist_entry, watchlist_name)
        # self.save_progress(('Watchlistname={} Watchlistentry={}').format(watchlist_name, watchlist_entry))
        ret_val, watch_list_id = self.get_watchlist_id(watchlist_name, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        if watch_list_id:
            watch_list_entry_json = '[{"value_name":"%s"}]' % watchlist_entry
            full_url = '{0}/watchlists/'.format(self._arc_url.strip("/"))
            try:
                r = requests.post(url='{0}{1}/values/'.format(full_url, watch_list_id),
                                data=watch_list_entry_json,
                                headers=self._client_headers,
                                verify=False)
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, 'Error connecting to server. {0}'.format(err))
            if 200 <= r.status_code <= 299:
                return action_result.set_status(phantom.APP_SUCCESS, 'Successfully added {0}'.format(msg_string))
            else:
                return action_result.set_status(phantom.APP_ERROR, 'Failed to add {0}'.format(msg_string))

        return action_result.set_status(phantom.APP_ERROR, 'Could not find watch_list = {0}'.format(watchlist_name))

    def _remove_watchlist_entry(self, param):
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.debug_print(param)
        watchlist_name = self._handle_py_ver_compat_for_input_str(param['watchlist_name'])
        watchlist_entry = self._handle_py_ver_compat_for_input_str(param['watchlist_entry'])
        msg_string = '{0} from watchlist={1}'.format(watchlist_entry, watchlist_name)
        ret_val, watch_list_id = self.get_watchlist_id(watchlist_name, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        if watch_list_id:
            ret_val, watch_list_value_id = self._check_watchlist_id(watch_list_id, watchlist_entry, action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            if watch_list_value_id:
                full_url = '{0}/watchlists/'.format(self._arc_url.strip("/"))
                try:
                    r = requests.delete(url='{0}{1}/values/{2}'.format(full_url, watch_list_id, watch_list_value_id),
                                        headers=self._client_headers,
                                        verify=False)
                except Exception as e:
                    err = self._get_error_message_from_exception(e)
                    return action_result.set_status(phantom.APP_ERROR, 'Error connecting to server. {0}'.format(err))
                if 200 <= r.status_code <= 299:
                    return action_result.set_status(phantom.APP_SUCCESS, 'Successfully removed {0}'.format(msg_string))
                else:
                    return action_result.set_status(phantom.APP_ERROR, 'Failed to remove {0}'.format(msg_string))
            else:
                return action_result.set_status(phantom.APP_ERROR, 'Could not find entry {0}'.format(msg_string))
        else:
            return action_result.set_status(phantom.APP_ERROR, 'Could not find watch_list = {0}'.format(watchlist_name))

    def _check_watchlist_entry(self, param):
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.debug_print(param)
        watchlist_name = self._handle_py_ver_compat_for_input_str(param['watchlist_name'])
        watchlist_entry = self._handle_py_ver_compat_for_input_str(param['watchlist_entry'])
        msg_string = '{0} in watchlist={1}'.format(watchlist_entry, watchlist_name)
        ret_val, watch_list_id = self.get_watchlist_id(watchlist_name, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        if watch_list_id:
            ret_val, watch_list_value_id = self._check_watchlist_id(watch_list_id, watchlist_entry, action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            if watch_list_value_id:
                return action_result.set_status(phantom.APP_SUCCESS, 'Successfully found {0}'.format(msg_string))
            else:
                return action_result.set_status(phantom.APP_SUCCESS, 'Failed to find entry {0}'.format(msg_string))
        else:
            return action_result.set_status(phantom.APP_ERROR, 'Could not find watch_list = {0}'.format(watchlist_name))

    def _add_componentlist_entry(self, param):
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.debug_print(param)
        componentlist_name = self._handle_py_ver_compat_for_input_str(param['componentlist_name'])
        componentlist_entry = self._handle_py_ver_compat_for_input_str(param['componentlist_entry'])
        msg_string = '{0} to componentlist={1}'.format(componentlist_entry, componentlist_name)
        ret_val, list_id = self.get_list_id(componentlist_name, 'component_list', action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        self._client_headers["Content-Type"] = "application/json"
        if list_id:
            component_list_entry_json = '{"items":["%s"]}' % componentlist_entry
            full_url = '{0}/remediation/lists/'.format(self._arc_url.strip("/"))
            try:
                r = requests.put(url='{0}{1}/append'.format(full_url, list_id),
                                headers=self._client_headers,
                                data=component_list_entry_json,
                                verify=False)
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, 'Error connecting to server. {0}'.format(err))
            if 200 <= r.status_code <= 299:
                return action_result.set_status(phantom.APP_SUCCESS, 'Successfully added {0}'.format(msg_string))
            else:
                return action_result.set_status(phantom.APP_ERROR, 'Failed to add {0}'.format(msg_string))

        return action_result.set_status(phantom.APP_ERROR, 'Could not find component_list = {0}'.format(componentlist_name))

    def _remove_componentlist_entry(self, param):
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.debug_print(param)
        componentlist_name = self._handle_py_ver_compat_for_input_str(param['componentlist_name'])
        componentlist_entry = self._handle_py_ver_compat_for_input_str(param['componentlist_entry'])
        msg_string = '{0} from componentlist={1}'.format(componentlist_entry, componentlist_name)
        ret_val, list_id = self.get_list_id(componentlist_name, 'component_list', action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        self._client_headers["Content-Type"] = "application/json"
        if list_id:
            component_list_entry_json = '{"items":["%s"]}' % componentlist_entry
            full_url = '{0}/remediation/lists/'.format(self._arc_url.strip("/"))
            try:
                r = requests.post(url='{0}{1}/delete'.format(full_url, list_id),
                                headers=self._client_headers,
                                data=component_list_entry_json,
                                verify=False)
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, 'Error connecting to server. {0}'.format(err))
            if 200 <= r.status_code <= 299:
                return action_result.set_status(phantom.APP_SUCCESS, 'Successfully removed {0}'.format(msg_string))
            else:
                return action_result.set_status(phantom.APP_ERROR, 'Failed to remove {0}'.format(msg_string))

        return action_result.set_status(phantom.APP_ERROR, 'Could not find component_list = {0}'.format(componentlist_name))

    def _check_componentlist_entry(self, param):
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.debug_print(param)
        componentlist_name = self._handle_py_ver_compat_for_input_str(param['componentlist_name'])
        componentlist_entry = self._handle_py_ver_compat_for_input_str(param['componentlist_entry'])
        msg_string = '{0} in componentlist={1}'.format(componentlist_entry, componentlist_name)
        ret_val, list_id = self.get_list_id(componentlist_name, 'component_list', action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        if list_id:
            full_url = '{0}/lists/'.format(self._arc_url.strip("/"))
            try:
                r = requests.get(url='{0}{1}/values?limit=100000'.format(full_url, list_id),
                                headers=self._client_headers,
                                verify=False)
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, 'Error connecting to server. {0}'.format(err))
            try:
                jsonText = json.loads(r.text)
                entryExists = False
                if 200 <= r.status_code <= 299:
                    for jText in jsonText:
                        entryExists = True
                        if self._handle_py_ver_compat_for_input_str(jText['content_value']).lower() == componentlist_entry.lower():
                            return action_result.set_status(phantom.APP_SUCCESS, 'Successfully found {0}'.format(msg_string))
                if not entryExists:
                    return action_result.set_status(phantom.APP_SUCCESS, 'Failed to find entry {0}'.format(msg_string))
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, 'Unable to parse JSON response from the server. {0}'.format(err))
        else:
            return action_result.set_status(phantom.APP_ERROR, 'Could not find component_list = {0}'.format(componentlist_name))

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS
        action_id = self.get_action_identifier()
        self.debug_print('action_id', self.get_action_identifier())
        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)
        elif action_id == 'on_poll':
            ret_val = self._handle_on_poll(param)
        elif action_id == 'add_watchlist_entry':
            ret_val = self._add_watchlist_entry(param)
        elif action_id == 'check_watchlist_entry':
            ret_val = self._check_watchlist_entry(param)
        elif action_id == 'remove_watchlist_entry':
            ret_val = self._remove_watchlist_entry(param)
        elif action_id == 'add_componentlist_entry':
            ret_val = self._add_componentlist_entry(param)
        elif action_id == 'remove_componentlist_entry':
            ret_val = self._remove_componentlist_entry(param)
        elif action_id == 'check_componentlist_entry':
            ret_val = self._check_componentlist_entry(param)
        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions

        self.debug_print("Action: 'initialize' Status: start")
        self._state = self.load_state()
        self.debug_print(("Action: 'initialize' State: {}").format(self._state))

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while fetching the Phantom server's Python major version")

        config = self.get_config()
        self._auth_url = self._handle_py_ver_compat_for_input_str(config['auth_url'])
        self._arc_url = self._handle_py_ver_compat_for_input_str(config['arc_url'] + '/rest/1.0/')
        self._client_id = self._handle_py_ver_compat_for_input_str(config['client_id'])
        self._client_secret = config['client_secret']
        self._export_profile = self._handle_py_ver_compat_for_input_str(config['export_profile'])
        self._client_headers = DG_CLIENT_HEADER

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades

        # self.save_state(self._state)
        return phantom.APP_SUCCESS

    def validateApiToken(self):

        if self._api_key == '':
            return False

        payload = {
            'client_id': self._client_id,
            'client_secret': self._client_secret,
            'grant_type':
            'urn:pingidentity.com:oauth2:grant_type:validate_bearer',
            'token': self._api_key,
        }
        try:
            api_key_response = requests.post(url='{}/as/introspect.oauth2'.format(self._auth_url.strip("/")),
                                            headers=DG_HEADER_URL,
                                            data=payload,
                                            verify=False)
            response_json = api_key_response.json()
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.debug_print(err)
            return False
        if api_key_response.status_code == 200 and response_json['active']:
            return True
        return False

    def requestApiToken(self):

        if not self.validateApiToken():
            payload = {
                'client_id': self._client_id,
                'client_secret': self._client_secret,
                'grant_type': 'client_credentials',
                'scope': 'client',
            }
            try:
                url = '{0}/as/token.oauth2'.format(self._auth_url.strip("/"))
                api_key_response = requests.post(url=url,
                                                headers=DG_HEADER_URL,
                                                data=payload,
                                                verify=False)
            except requests.exceptions.InvalidSchema:
                error_message = 'Error connecting to server. No connection adapters were found for %s' % (url)
                return (phantom.APP_ERROR, error_message)
            except requests.exceptions.InvalidURL:
                error_message = 'Error connecting to server. Invalid URL %s' % (url)
                return (phantom.APP_ERROR, error_message)
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return (phantom.APP_ERROR, 'Error connecting to server. {0}'.format(err))
            try:
                response_json = api_key_response.json()

                if api_key_response.status_code == 200:
                    self._api_key = response_json['access_token']
                    self._client_headers.update({'Authorization': 'Bearer {}'.format(self._api_key)})
                    self._client_headers['Authorization'] = 'Bearer {}'.format(self._api_key)
                    self.save_progress('Got API Token ' + str(self._client_headers['Authorization']))
                    return (phantom.APP_SUCCESS, None)
                else:
                    return (phantom.APP_ERROR, self._handle_py_ver_compat_for_input_str(api_key_response.text))
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return (phantom.APP_ERROR, 'Unable to process response from the server. {0}'.format(err))
        else:
            self._client_headers['Authorization'] = 'Bearer {}'.format(self._api_key)
            return (phantom.APP_SUCCESS, None)


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask

        import getpass
        password = getpass.getpass('Password: ')

    if username and password:
        try:
            login_url = DigitalGuardianArcConnector._get_phantom_base_url() + '/login'

            print('Accessing the Login page')
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print('Logging into Platform to get the session id')
            r2 = requests.post(login_url,
                               verify=False,
                               data=data,
                               headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print('Unable to get session id from the platform. Error: ' + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = DigitalGuardianArcConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))
    exit(0)
