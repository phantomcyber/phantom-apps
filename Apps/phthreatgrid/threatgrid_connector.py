# File: threatgrid_connector.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom imports
import phantom.app as phantom
import phantom.rules as phantom_rules
from phantom.app import BaseConnector
from phantom.app import ActionResult

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

SUBMIT_FILE = '{base_uri}/api/v2/samples'
TEST_CONNECTIVITY_URL = '{base_uri}/api/v2/samples?api_key={api_key}&limit=1'
RESULTS_URL = '{base_uri}/samples/{task_id}'
STATUS_URL = '{base_uri}/api/v2/samples/{task_id}?api_key={api_key}'
ANALYSIS_URL = '{base_uri}/api/v2/samples/{task_id}/analysis.json?api_key={api_key}'
THREAT_URL = '{base_uri}/api/v2/samples/{task_id}/threat?api_key={api_key}'
HASH_SEARCH_URL = '{base_uri}/api/v2/samples/search?api_key={api_key}&checksum={hash}'
PLAYBOOKS_URL = '{base_uri}/api/v3/configuration/playbooks?api_key={api_key}'


class threatgridConnector(BaseConnector):
    # The actions supported by this connector
    ACTION_ID_QUERY_FILE = "detonate file"
    ACTION_ID_QUERY_URL = "detonate url"
    ACTION_ID_GET_DETONATION_RESULTS = "get report"
    ACTION_ID_TEST_ASSET_CONNECTIVITY = 'test_asset_connectivity'
    ACTION_ID_LIST_PLAYBOOKS = "list_playbooks"

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
        except:
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
            if r:
                obj = r.json()
            else:
                obj = None
        except Exception as e:
            self.save_progress(THREATGRID_TEST_CONNECTIVITY_FAILED)
            self.debug_print("Response from server: {0}".format(r.text))
            return self.threatgrid_action_result.set_status(phantom.APP_ERROR, "Error Parsing data from the server, Not a valid Json",
                                                            self._get_error_message_from_exception(e))

        if obj and obj.get(RESPONSE_ERROR_KEY):
            try:
                error = obj[RESPONSE_ERROR_KEY].get(
                    RESPONSE_ERRORS_KEY, THREATGRID_UNSPECIFIED_ERROR)
                error = error[0] if len(error) > 0 else {}
                error = "Code: {0}, Message: {1}".format(
                    error.get('code', 'Not returned'), error.get('message', 'Unspecified'))
            except Exception:
                self.save_progress(THREATGRID_TEST_CONNECTIVITY_FAILED)
                self.debug_print("Response from server: {0}".format(obj))
                self.debug_print(format_exc())
                error = 'Error parsing result from server.'
        elif r.status_code != requests.codes.ok:  # pylint: disable=E1101
            error = 'Received http error code {}'.format(r.status_code)

        if (error):
            self.debug_print("connect failed", error)
            self.save_progress(THREATGRID_TEST_CONNECTIVITY_FAILED)
            return self.threatgrid_action_result.set_status(phantom.APP_ERROR, error)

        self.save_progress(THREATGRID_TEST_CONNECTIVITY_PASSED)
        return self.threatgrid_action_result.set_status(phantom.APP_SUCCESS)

    def _lookup_and_parse_results(self, task_id):
        self.send_progress(
            'Polling for analysis results ({})...', datetime.utcnow())
        start_time = datetime.utcnow()
        time_limit = start_time + timedelta(seconds=self.threatgrid_timeout)
        job_url = STATUS_URL.format(
            base_uri=self.threatgrid_base_uri, task_id=task_id, api_key=self.threatgrid_api_key)
        result_data = {}
        self.threatgrid_action_result.add_data(result_data)
        count = 1

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
                    self.threatgrid_action_result.set_status(
                        phantom.APP_ERROR, error)
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
                self.threatgrid_action_result.set_status(
                    phantom.APP_ERROR, error)
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
                        self.threatgrid_action_result.set_status(phantom.APP_SUCCESS,
                                                                 'Successfully retrieved analysis results')
                        self.threatgrid_action_result.update_summary({
                            TARGET_KEY: target,
                            TASK_ID_KEY: task_id,
                        })
                break

    def _queue_analysis(self, data, files, key):
        self.save_progress('Query threatgrid. data: {}', files)
        self.send_progress('Sending query to threatgrid for %r' % key)

        url = SUBMIT_FILE.format(base_uri=self.threatgrid_base_uri)

        try:
            r = requests.post(url, data=data, files=files, verify=self.verify)
        except Exception as e:
            return self.threatgrid_action_result.set_status(phantom.APP_ERROR,
                                                            THREATGRID_REST_CALL_ERROR.format(self._get_error_message_from_exception(e)))

        self.send_progress('Query returned {}.', r.status_code)

        response = r.json().get(RESPONSE_DATA_KEY, {})
        error = r.json().get(RESPONSE_ERROR_KEY)
        task_id = response.get('id')
        if r.status_code != requests.codes.ok or error or not task_id:  # pylint: disable=E1101
            self.save_progress('Analysis failed to post.')
            if error:
                error_code = error[RESPONSE_ERROR_CODE_KEY]
                message = error[RESPONSE_ERROR_MSG_KEY]
            else:
                error_code = '{} (response {})'.format(
                    THREATGRID_UNSPECIFIED_ERROR, r.status_code)
                message = 'threatgrid Error: ' + error_code
            self.threatgrid_action_result.set_status(
                phantom.APP_ERROR, message)
        else:
            self.save_progress('Analysis queued.', files)
            results_url = RESULTS_URL.format(
                base_uri=self.threatgrid_base_uri, task_id=task_id)
            self.threatgrid_action_result.set_status(phantom.APP_SUCCESS,
                                                     'Successfully queued analysis. Result at {}',
                                                     None, results_url)
            self._lookup_and_parse_results(task_id)
            self.threatgrid_action_result.update_summary({
                TARGET_KEY: key,
                TASK_ID_KEY: task_id,
                RESULTS_URL_KEY: results_url,
            })

    def _check_existing(self, hash):
        self.save_progress('Checking for existing report: {}', hash)

        url = HASH_SEARCH_URL.format(base_uri=self.threatgrid_base_uri,
                                     api_key=self.threatgrid_api_key,
                                     hash=hash)

        try:
            r = requests.get(url, verify=self.verify)
        except Exception as e:
            return self.threatgrid_action_result.set_status(phantom.APP_ERROR,
                                                            THREATGRID_REST_CALL_ERROR.format(self._get_error_message_from_exception(e)))
        self.send_progress('Query returned {}.', r.status_code)
        try:
            obj = r.json()
            for item in obj.get('data', {}).get('items', []):
                task_id = item.get('sample')
                if task_id:
                    return task_id

        except Exception:
            self.debug_print('error searching..', format_exc())
        return False

    def _get_detonation_results(self, task_id):
        results_url = RESULTS_URL.format(
            base_uri=self.threatgrid_base_uri, task_id=task_id)
        self.threatgrid_action_result.update_summary({
            TASK_ID_KEY: task_id,
            RESULTS_URL_KEY: results_url
        })
        self._lookup_and_parse_results(task_id)

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
        if not filename:
            filename = vault_id

        try:
            _, _, file_info = phantom_rules.vault_info(vault_id=vault_id)
            if not file_info:
                self.threatgrid_action_result.set_status(
                    phantom.APP_ERROR, THREATGRID_FILE_NOT_FOUND_ERROR.format(vault_id))
                return
            file_path = list(file_info)[0].get('path')
            payload = open(file_path, 'rb')
        except:
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
            'playbook': param.get('playbook', 'default')
        }
        if param.get('private'):
            data['private'] = True

        self._queue_analysis(data, files, filename)

    def _list_playbooks(self, param):
        try:
            url = PLAYBOOKS_URL.format(base_uri=self.threatgrid_base_uri,
                                       api_key=self.threatgrid_api_key)
            r = requests.get(url, verify=self.verify)
            self.send_progress('List playbooks returned {}.', r.status_code)
            response = r.json().get(RESPONSE_DATA_KEY, {})
            error = r.json().get(RESPONSE_ERROR_KEY)
        except Exception as e:
            return self.threatgrid_action_result.set_status(phantom.APP_ERROR,
                                                            THREATGRID_REST_CALL_ERROR.format(self._get_error_message_from_exception(e)))
        if r.status_code != requests.codes.ok or error:  # pylint: disable=E1101
            self.save_progress('Request failed to process')
            if error:
                error_code = error[RESPONSE_ERROR_CODE_KEY]
                message = error[RESPONSE_ERROR_MSG_KEY]
            else:
                error_code = '{} (response {})'.format(
                    THREATGRID_UNSPECIFIED_ERROR, r.status_code)
                message = 'threatgrid Error: ' + error_code
            self.threatgrid_action_result.set_status(
                phantom.APP_ERROR, message)
        else:
            for each_playbook in response['playbooks']:
                self.threatgrid_action_result.add_data(each_playbook)
            self.threatgrid_action_result.set_status(phantom.APP_SUCCESS,
                                                     'Successfully retrieved playbooks')
            self.threatgrid_action_result.update_summary({
                "Total Playbooks": len(response['playbooks'])
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
            if (action == self.ACTION_ID_QUERY_FILE):
                self._query_file(param)
            elif (action == self.ACTION_ID_QUERY_URL):
                self._query_url(param)
            elif (action == self.ACTION_ID_GET_DETONATION_RESULTS):
                self._get_detonation_results(param[TASK_ID_KEY])
            elif (action == self.ACTION_ID_TEST_ASSET_CONNECTIVITY):
                self._test_asset_connectivity()
            elif (action == self.ACTION_ID_LIST_PLAYBOOKS):
                self._list_playbooks(param)
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

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
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

    if (len(sys.argv) < 2):
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = threatgridConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
