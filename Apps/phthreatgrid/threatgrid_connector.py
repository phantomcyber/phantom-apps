# File: threatgrid_connector.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom imports
import phantom.app as phantom
import phantom.rules as phantom_rules
from phantom.app import BaseConnector
from phantom.app import ActionResult
from phantom.vault import Vault
import uuid
import os

from threatgrid_consts import *

# Other imports used by this connector
import json
import requests
from datetime import datetime, timedelta
import time

try:
    from cStringIO import StringIO
except ModuleNotFoundError:
    from io import StringIO
from traceback import format_exc


class threatgridConnector(BaseConnector):
    # The actions supported by this connector
    ACTION_ID_QUERY_FILE = "detonate file"
    ACTION_ID_QUERY_URL = "detonate url"
    ACTION_ID_GET_DETONATION_RESULTS = "get report"
    ACTION_ID_TEST_ASSET_CONNECTIVITY = 'test_asset_connectivity'
    ACTION_ID_LIST_PLAYBOOKS = "list_playbooks"
    ACTION_ID_SEARCH_REPORT = "list submissions"

    def _mask_api_key_from_log(self, msg):
        """ This method is used to mask api in log for security purpose.
        :param msg: Log message
        :return: Masked log message
        """
        if msg:
            return msg.replace(self.threatgrid_api_key, THREATGRID_API_KEY_REPLACE_MSG)
        return msg

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_code = THREATGRID_ERROR_CODE_UNAVAILABLE
        error_msg = THREATGRID_ERROR_MESSAGE_UNAVAILABLE

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = THREATGRID_ERROR_CODE_UNAVAILABLE
                    error_msg = e.args[0]
        except Exception:
            error_code = THREATGRID_ERROR_CODE_UNAVAILABLE
            error_msg = THREATGRID_ERROR_MESSAGE_UNAVAILABLE

        return "Error Code: {0}. Error Message: {1}".format(error_code, self._mask_api_key_from_log(error_msg))

    def _test_asset_connectivity(self):
        error = None
        url = TEST_CONNECTIVITY_URL.format(
            base_uri=self.threatgrid_base_uri, api_key=self.threatgrid_api_key)

        try:
            r = requests.get(url, verify=self.verify)
        except Exception as e:
            self.save_progress(THREATGRID_TEST_CONNECTIVITY_FAILED)
            return self.threatgrid_action_result.set_status(phantom.APP_ERROR, "Error Connecting to server", self._get_error_message_from_exception(e))
        try:
            obj = r.json()
        except Exception as e:
            self.save_progress(THREATGRID_TEST_CONNECTIVITY_FAILED)
            self.debug_print("Response from server: {0}".format(r.text))
            return self.threatgrid_action_result.set_status(phantom.APP_ERROR, "Error Parsing data from the server, Not a valid Json",
                                                            self._get_error_message_from_exception(e))

        if obj and obj.get(RESPONSE_ERROR_KEY):
            error = obj[RESPONSE_ERROR_KEY].get(
                RESPONSE_ERRORS_KEY, THREATGRID_UNSPECIFIED_ERROR)
            error = error[0] if len(error) > 0 else {}
            error = "Code: {0}, Message: {1}".format(
                error.get('code', 'Not returned'), error.get('message', 'Unspecified'))
        elif r.status_code != requests.codes.ok:  # pylint: disable=E1101
            error = 'Received http error code {}'.format(r.status_code)

        if error:
            self.debug_print("connect failed", error)
            self.save_progress(THREATGRID_TEST_CONNECTIVITY_FAILED)
            return self.threatgrid_action_result.set_status(phantom.APP_ERROR, error)

        self.save_progress(THREATGRID_TEST_CONNECTIVITY_PASSED)
        return self.threatgrid_action_result.set_status(phantom.APP_SUCCESS)

    def _get_html_report(self, action_result, html_report_url, task_id):
        r = requests.get(html_report_url, verify=self.verify)
        if not r.ok:  # pylint: disable=E1101
            error = 'Received http error code {}'.format(r.status_code)
            return action_result.set_status(phantom.APP_ERROR, error)
        html_data = r.text
        file_name = "{0}_report.html".format(task_id)

        is_download = False
        if hasattr(Vault, "create_attachment"):
            vault_ret = Vault.create_attachment(html_data, self.get_container_id(), file_name=file_name)

            if vault_ret.get('succeeded'):
                action_result.set_status(phantom.APP_SUCCESS, "Downloaded report")
                _, _, vault_meta_info = phantom_rules.vault_info(container_id=self.get_container_id(), vault_id=vault_ret[phantom.APP_JSON_HASH])
                if not vault_meta_info:
                    return action_result.set_status(phantom.APP_ERROR, THREATGRID_VAULT_ERROR)

                vault_path = list(vault_meta_info)[0]['path']
                summary = {
                    phantom.APP_JSON_VAULT_ID: vault_ret[phantom.APP_JSON_HASH],
                    phantom.APP_JSON_NAME: file_name,
                    'vault_file_path': vault_path
                }
                action_result.update_summary(summary)
                return phantom.APP_SUCCESS
            else:
                is_download = False

        if not is_download:
            if hasattr(phantom_rules, 'get_vault_tmp_dir'):
                temp_dir = phantom_rules.get_vault_tmp_dir()
            else:
                temp_dir = '/opt/phantom/vault/tmp'
            temp_dir = "{0}{1}".format(temp_dir, '/{}'.format(uuid.uuid4()))
            os.makedirs(temp_dir)
            file_path = os.path.join(temp_dir, file_name)

            try:
                with open(file_path, 'w') as f:
                    f.write(html_data)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, self._get_error_message_from_exception(e))

            success, message, vault_id = phantom_rules.vault_add(container=self.get_container_id(), file_location=file_path, file_name=file_name)

            if success:
                action_result.set_status(phantom.APP_SUCCESS, "Downloaded report")
                _, _, vault_meta_info = phantom_rules.vault_info(container_id=self.get_container_id(), vault_id=vault_id)
                if not vault_meta_info:
                    return action_result.set_status(phantom.APP_ERROR, THREATGRID_VAULT_ERROR)

                vault_path = list(vault_meta_info)[0]['path']
                summary = {
                    phantom.APP_JSON_VAULT_ID: vault_id,
                    phantom.APP_JSON_NAME: file_name,
                    'vault_file_path': vault_path
                }

                action_result.update_summary(summary)
                return action_result.set_status(phantom.APP_SUCCESS)
            else:
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while saving file to vault: {}".format(message))

    def _lookup_and_parse_results(self, task_id, is_download_report=False):
        self.send_progress(
            'Polling for analysis results ({})...', datetime.utcnow())
        start_time = datetime.utcnow()
        time_limit = start_time + timedelta(seconds=self.threatgrid_timeout)
        job_url = STATUS_URL.format(
            base_uri=self.threatgrid_base_uri, task_id=task_id, api_key=self.threatgrid_api_key)
        result_data = {}
        self.threatgrid_action_result.add_data(result_data)
        count = 1
        message = ''

        while True:
            error = None
            try:
                r = requests.get(job_url, verify=self.verify)
            except requests.exceptions.ProxyError as err:
                return self.threatgrid_action_result.set_status(phantom.APP_ERROR,
                                                                THREATGRID_REST_CALL_ERROR.format(self._get_error_message_from_exception(err)))
            except Exception as e:
                self.debug_print('get status exception', format_exc())
                error = self._mask_api_key_from_log('Error polling for result ({}): {}'.format(job_url,
                                                                                               self._get_error_message_from_exception(e)))
            else:
                if r.status_code != requests.codes.ok:  # pylint: disable=E1101
                    error = self._mask_api_key_from_log(
                        'Error on HTTP request to {!r} code {}'.format(job_url, r.status_code))
                    self.debug_print('Failed task view', r.text)

            if error:
                if datetime.utcnow() > time_limit:
                    self.threatgrid_action_result.set_status(phantom.APP_ERROR, error)
                    return
                count += 1
                time.sleep(POLL_SLEEP_SECS)
                continue
            try:
                task_json = r.json()[RESPONSE_DATA_KEY]
            except Exception as e:
                error = 'Failed to parse task view response for task_id {!r} ({!r})'.format(task_id,
                                                                                            self._get_error_message_from_exception(e))
                self.debug_print('Parse task view failed', r.text)
                self.threatgrid_action_result.set_status(phantom.APP_ERROR, error)
                break

            status = task_json.get(RESPONSE_STATE_KEY)
            result_data[RESULT_STATUS_KEY] = task_json
            if status not in THREATGRID_DONE_STATES:
                # find expected timeout
                if datetime.utcnow() > time_limit:
                    self.save_progress('{status}... Polling for updates to  {job_url!r} timed out.',
                                       status=status, job_url=self._mask_api_key_from_log(job_url))
                    break
                self.send_progress('Polling attempt {count}. ({status}) {job_url!r}.',
                                   count=count, status=status, job_url=self._mask_api_key_from_log(job_url))
                count += 1
                time.sleep(POLL_SLEEP_SECS)
            else:
                report_url = ANALYSIS_URL.format(
                    base_uri=self.threatgrid_base_uri, task_id=task_id, api_key=self.threatgrid_api_key)
                r2 = requests.get(report_url, verify=self.verify)

                if r2.status_code != requests.codes.ok:  # pylint: disable=E1101
                    error = self._mask_api_key_from_log(
                        'Query for report {!r} failed with status code {!d}'.format(report_url, r2.status_code))
                    self.debug_print('Failed report text', r2.text)
                    self.threatgrid_action_result.set_status(
                        phantom.APP_ERROR, error)
                    break
                try:
                    obj = r2.json()
                    result_data[RESULT_REPORT_KEY] = obj
                    threat_url = THREAT_URL.format(
                        base_uri=self.threatgrid_base_uri, task_id=task_id, api_key=self.threatgrid_api_key)
                    threat_info = requests.get(
                        threat_url, verify=self.verify).json().get(RESPONSE_DATA_KEY)
                    result_data[THREAT_KEY] = threat_info
                    error_dict = obj.get(RESPONSE_ERROR_KEY, {})
                except Exception as e:
                    error = 'Failed to parse task report response for task_id {!r} ({!r})'.format(task_id,
                                                                                                  self._get_error_message_from_exception(e))
                    self.debug_print('Parse task view failed', r2.text)
                    self.threatgrid_action_result.set_status(
                        phantom.APP_ERROR, error)
                    self.debug_print(
                        'result_data', self.threatgrid_action_result)
                    break
                if error_dict:
                    self.threatgrid_action_result.set_status(
                        phantom.APP_ERROR, error_dict.get('message', THREATGRID_UNSPECIFIED_ERROR))
                    self.debug_print('response', r2.text)
                    for e in error_dict.get(RESPONSE_ERRORS_KEY, []):
                        self.debug_print('received error', json.dumps(e))
                        self.save_progress(
                            'Received Error Code: {}'.format(e.get('code', '?')))
                else:
                    malware_list = obj['metadata']['malware_desc']
                    if not malware_list:
                        self.threatgrid_action_result.set_status(phantom.APP_ERROR,
                                                                 "Unable to parse content, file type may not be supported")
                    else:
                        target = malware_list[0].get(
                            'filename', 'Unable to parse target')
                        try:
                            if malware_list[0]['type'] == 'url':
                                for _, info in obj['dynamic']['processes'].items():
                                    if info['analyzed_because'] == 'Is potential target sample.':
                                        target = info['startup_info']['command_line']
                                        target = target.replace('"', '')
                                        target = target[len(
                                            info['startup_info']['image_pathname']):].strip()
                        except Exception:
                            self.debug_print(
                                'error parsing target', format_exc())
                        message += 'Successfully retrieved analysis results'
                        self.threatgrid_action_result.set_status(phantom.APP_SUCCESS, message)
                        self.threatgrid_action_result.update_summary({
                            TARGET_KEY: target,
                            TASK_ID_KEY: task_id,
                        })

                # for html report
                if is_download_report:
                    html_report_url = HTML_REPORT_URL.format(base_uri=self.threatgrid_base_uri, task_id=task_id, api_key=self.threatgrid_api_key)
                    ret_val = self._get_html_report(self.threatgrid_action_result, html_report_url, task_id)
                    if phantom.is_fail(ret_val):
                        if not message:
                            return self.threatgrid_action_result.get_status()
                        else:
                            message += ' but failed to download report into vault, {}'.format(self.threatgrid_action_result.get_message())
                            return self.threatgrid_action_result.set_status(phantom.APP_SUCCESS, message)

                    message += ' and downloaded report to vault'
                    self.threatgrid_action_result.set_status(phantom.APP_SUCCESS, message)

                break

    def _queue_analysis(self, data, files, key):
        url = SUBMIT_FILE.format(base_uri=self.threatgrid_base_uri)
        try:
            r = requests.post(url, data=data, files=files, verify=self.verify)
            r_json = r.json()
        except Exception as e:
            return self.threatgrid_action_result.set_status(phantom.APP_ERROR,
                                                            THREATGRID_REST_CALL_ERROR.format(self._get_error_message_from_exception(e)))

        task_id = r_json.get(RESPONSE_DATA_KEY, {}).get('id')
        error = r_json.get(RESPONSE_ERROR_KEY)
        if r.status_code != requests.codes.ok or error or not task_id:  # pylint: disable=E1101
            self._response_status(error)
        else:
            results_url = RESULTS_URL.format(
                base_uri=self.threatgrid_base_uri, task_id=task_id)
            self._lookup_and_parse_results(task_id)
            self.threatgrid_action_result.update_summary({
                TARGET_KEY: key,
                TASK_ID_KEY: task_id,
                RESULTS_URL_KEY: results_url
            })

    def _check_existing(self, hash):
        url = HASH_SEARCH_URL.format(base_uri=self.threatgrid_base_uri,
                                     api_key=self.threatgrid_api_key,
                                     hash=hash)
        try:
            r = requests.get(url, verify=self.verify)
            obj = r.json()
        except Exception as e:
            return self.threatgrid_action_result.set_status(phantom.APP_ERROR,
                                                            THREATGRID_REST_CALL_ERROR.format(self._get_error_message_from_exception(e)))
        self.send_progress('Query returned {}.', r.status_code)
        for item in obj.get('data', {}).get('items', []):
            task_id = item.get('sample')
            if task_id:
                return task_id

        return False

    def _get_detonation_results(self, task_id, is_download_report=False):
        results_url = RESULTS_URL.format(
            base_uri=self.threatgrid_base_uri, task_id=task_id)
        self._lookup_and_parse_results(task_id, is_download_report)
        self.threatgrid_action_result.update_summary({
            TASK_ID_KEY: task_id,
            RESULTS_URL_KEY: results_url
        })

    def _query_url(self, param):
        sio = StringIO("[InternetShortcut]\nURL={}".format(param['url']))
        filename = 'sample.url'

        files = {
            'sample': (filename, sio)
        }
        data = {
            'api_key': self.threatgrid_api_key,
            'filename': filename,
            'tags': [],
            'os': '',
            'osver': '',
            'source': '',
            'vm': param.get('vm', ''),
            'playbook': param.get('playbook', 'default')
        }
        if param.get('private'):
            data['private'] = True
        self._queue_analysis(data, files, param['url'])

    def _query_file(self, param):
        vault_id = param['vault_id']

        if param.get('force_analysis') is False:
            task_id = self._check_existing(vault_id)
            if task_id:
                return self._get_detonation_results(task_id)
        filename = param.get('file_name')
        filename = filename if filename is not None else vault_id

        try:
            _, _, file_info = phantom_rules.vault_info(vault_id=vault_id)
            if not file_info:
                self.threatgrid_action_result.set_status(
                    phantom.APP_ERROR, THREATGRID_FILE_NOT_FOUND_ERROR.format(vault_id))
                return
            file_path = list(file_info)[0].get('path')
            payload = open(file_path, 'rb')
        except Exception:
            self.threatgrid_action_result.set_status(
                phantom.APP_ERROR, THREATGRID_FILE_NOT_FOUND_ERROR.format(vault_id))
            return

        files = {
            'sample': (filename, payload),
        }
        data = {
            'api_key': self.threatgrid_api_key,
            'filename': filename,
            'tags': [],
            'os': '',
            'osver': '',
            'source': '',
            'vm': param.get('vm', ''),
            'playbook': param.get('playbook', 'default'),
            'sample_password': param.get('sample_password')
        }
        if param.get('private'):
            data['private'] = True

        self._queue_analysis(data, files, filename)

    def _list_playbooks(self):
        try:
            url = PLAYBOOKS_URL.format(base_uri=self.threatgrid_base_uri,
                                       api_key=self.threatgrid_api_key)
            r = requests.get(url, verify=self.verify)
            response = r.json().get(RESPONSE_DATA_KEY, {})
            error = r.json().get(RESPONSE_ERROR_KEY)
        except Exception as e:
            return self.threatgrid_action_result.set_status(phantom.APP_ERROR,
                                                            THREATGRID_REST_CALL_ERROR.format(self._get_error_message_from_exception(e)))
        if r.status_code != requests.codes.ok or error:  # pylint: disable=E1101
            self._response_status(error)
        else:
            for each_playbook in response['playbooks']:
                self.threatgrid_action_result.add_data(each_playbook)
            self.threatgrid_action_result.set_status(phantom.APP_SUCCESS,
                                                     'Successfully retrieved playbooks')
            self.threatgrid_action_result.update_summary({
                "Total Playbooks": len(response['playbooks'])
            })

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        try:
            if not float(parameter).is_integer():
                action_result.set_status(phantom.APP_ERROR, INVALID_INT.format(param=key))
                return None

            parameter = int(parameter)
        except Exception:
            action_result.set_status(phantom.APP_ERROR, INVALID_INT.format(param=key))
            return None

        if parameter < 0:
            action_result.set_status(phantom.APP_ERROR, ERR_NEGATIVE_INT_PARAM.format(param=key))
            return None

        if not allow_zero and parameter == 0:
            action_result.set_status(phantom.APP_ERROR, NON_ZERO_ERROR.format(param=key))
            return None

        return parameter

    def _response_status(self, error):
        if error:
            message = error[RESPONSE_ERROR_MSG_KEY]
            message = message.capitalize()
        else:
            error_code = '{} (response {})'.format(
                THREATGRID_UNSPECIFIED_ERROR, r.status_code)
            message = 'Threatgrid Error: ' + error_code
        self.threatgrid_action_result.set_status(
            phantom.APP_ERROR, message)

    def _search_submissions(self, param):
        query = param.get('query')
        limit = self._validate_integer(self.threatgrid_action_result, param.get('limit', DEFAULT_LIMIT), "limit", allow_zero=False)
        if limit is None:
            return self.threatgrid_action_result.get_status()

        search_report_url = SEARCH_REPORT_URL.format(base_uri=self.threatgrid_base_uri, api_key=self.threatgrid_api_key, limit=limit)
        if query:
            search_report_url += '&q={query}'.format(query=query)
        try:
            r = requests.get(search_report_url, verify=self.verify)
            r_json = r.json()
            response = r_json.get(RESPONSE_DATA_KEY, {})
            error = r_json.get(RESPONSE_ERROR_KEY)
        except Exception as e:
            return self.threatgrid_action_result.set_status(phantom.APP_ERROR,
                                                            THREATGRID_REST_CALL_ERROR.format(self._get_error_message_from_exception(e)))

        if r.status_code != requests.codes.ok or error:  # pylint: disable=E1101
            self._response_status(error)
        else:
            items = response.get('items', [])
            items_size = len(items)
            for each_data in items:
                self.threatgrid_action_result.add_data(each_data)

            self.threatgrid_action_result.set_status(phantom.APP_SUCCESS, THREATGRID_SUCC_RET_REPORT.format(items_size))
            self.threatgrid_action_result.update_summary({
                "search_report": items_size
            })

    def handle_action(self, param):
        config = self.get_config()
        action = self.get_action_identifier()

        self.threatgrid_action_result = self.add_action_result(
            ActionResult(dict(param)))
        self.threatgrid_base_uri = config['base_uri']
        self.threatgrid_timeout = int(config['timeout'])
        self.threatgrid_api_key = config['api_key']
        self.verify = config[phantom.APP_JSON_VERIFY]

        try:
            if action == self.ACTION_ID_QUERY_FILE:
                self._query_file(param)
            elif action == self.ACTION_ID_QUERY_URL:
                self._query_url(param)
            elif action == self.ACTION_ID_GET_DETONATION_RESULTS:
                self._get_detonation_results(param[TASK_ID_KEY], param.get('download_report', False))
            elif action == self.ACTION_ID_TEST_ASSET_CONNECTIVITY:
                self._test_asset_connectivity()
            elif action == self.ACTION_ID_LIST_PLAYBOOKS:
                self._list_playbooks()
            elif action == self.ACTION_ID_SEARCH_REPORT:
                self._search_submissions(param)
            else:
                raise ValueError('action %r is not supported' % action)
        except Exception as e:
            return self.threatgrid_action_result.set_status(phantom.APP_ERROR,
                                                            THREATGRID_REST_CALL_ERROR.format(self._get_error_message_from_exception(e)))

        return self.threatgrid_action_result.get_status()


if __name__ == '__main__':

    import sys
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

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            print("Accessing the Login page")
            login_url = BaseConnector._get_phantom_base_url() + "login"
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False,
                               data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    if len(sys.argv) < 2:
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = threatgridConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
