# File: vxstream_connector.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Phantom imports

import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

try:
    from phantom.vault import Vault
except:
    import phantom.vault as Vault

from vxstream_consts import *

# Other imports used by this connector
import json
import requests
import uuid
import shutil
import os
from io import BytesIO
import gzip
import time
from datetime import datetime
import urllib
from urlparse import urlparse
from os.path import splitext, basename

from api_classes.api_key_current import ApiKeyCurrent
from api_classes.api_search_terms import ApiSearchTerms
from api_classes.api_search_hash import ApiSearchHash
from api_classes.api_submit_file import ApiSubmitFile
from api_classes.api_submit_online_file import ApiSubmitOnlineFile
from api_classes.api_submit_url_for_analysis import ApiSubmitUrlForAnalysis
from api_classes.api_report_summary import ApiReportSummary
from api_classes.api_report_file import ApiReportFile
from api_classes.api_report_state import ApiReportState
from api_classes.api_submit_hash_for_url import ApiSubmitHashForUrl


class VxError(Exception):
    pass


class VxStreamConnector(BaseConnector):

    ACTION_ID_TEST_ASSET_CONNECTIVITY = 'test_asset_connectivity'
    ACTION_ID_DETONATE_URL = 'detonate_url'
    ACTION_ID_DETONATE_FILE = 'detonate_file'
    ACTION_ID_DETONATE_ONLINE_FILE = 'detonate_online_file'
    ACTION_ID_GET_REPORT = 'get_report'
    ACTION_ID_SEARCH_TERMS = 'search_terms'
    ACTION_ID_HUNT_FILE = 'hunt_file'
    ACTION_ID_HUNT_HASH = 'hunt_hash'
    ACTION_ID_HUNT_IP = 'hunt_ip'
    ACTION_ID_HUNT_URL = 'hunt_url'
    ACTION_ID_HUNT_DOMAIN = 'hunt_domain'
    ACTION_ID_HUNT_MALWARE_FAMILY = 'hunt_malware_family'
    ACTION_ID_HUNT_SIMILAR = 'hunt_similar'
    ACTION_ID_GET_FILE = 'get_file'
    ACTION_ID_GET_PCAP = 'get_pcap'
    ACTION_ID_GET_FILE_FROM_URL = 'get_file_from_url'
    ACTION_ID_CHECK_STATUS = 'check_status'
    ACTION_ID_CHECK_URL_HASH = 'check_url_hash'

    _base_url = ''
    _request_session = None

    def __init__(self):
        super(VxStreamConnector, self).__init__()
        self._api_token = None

    def initialize(self):
        config = self.get_config()
        self._base_url = config[PAYLOAD_SECURITY_WEBSERVICE_BASE_URL]
        if self._base_url.endswith('/'):
            self._base_url = self._base_url[:-1]

        if self._base_url.endswith('vxstream-sandbox.com'):
            self._base_url = self._base_url.replace('vxstream-sandbox.com', 'falcon-sandbox.com')

        if 'https://' not in self._base_url:
            self.save_progress('Warning: Using encrypted connection over https is strongly recommended.')

        self._request_session = requests.Session()

        return phantom.APP_SUCCESS

    def handle_exception(self, exception):
        self.set_status(phantom.APP_ERROR, 'Unexpected error has occurred')

        return self.get_status()

    def _get_file_dict(self, param, action_result):
        vault_id = param['vault_id']

        try:
            if hasattr(Vault, 'get_file_path'):
                payload = open(Vault.get_file_path(vault_id), 'rb')
            else:
                payload = open(Vault.get_vault_file(vault_id), 'rb')
        except:
            return action_result.set_status(phantom.APP_ERROR, 'File not found in vault ("{}")'.format(vault_id)), None

        files = {'file': (param['file_name'], payload)}

        return phantom.APP_SUCCESS, files

    def _make_api_call(self, api_object):
        config = self.get_config()
        api_object.call(self._request_session, verify_server=config[PAYLOAD_SECURITY_VERIFY_SERVER_CERT])

    def _make_api_call_with_err_handling(self, api_object, base_err_msg):
        try:
            self._make_api_call(api_object)
        except requests.exceptions.RequestException as exc:
            raise VxError('{} Connection to server failed. Error: \'{}\''.format(base_err_msg, str(exc)))

        if api_object.if_request_success() is False:
            raise VxError('{} {}'.format(base_err_msg, api_object.get_prepared_response_msg()))

        return api_object

    def _build_sample_url(self, id):
        if ':' in id:
            sha256, env_id = id.split(':')

            url = '/sample/{}?environmentId={}'.format(sha256, env_id)
        elif len(id) == 24:
            url = '/sample/{}/find'.format(id)
        else:
            url = '/sample/{}'.format(id)

        return '{}{}'.format(self._base_url, url)

    def _check_status_partial(self, param):
        config = self.get_config()
        api_check_state = ApiReportState(config[PAYLOAD_SECURITY_API_KEY], self._base_url, self)
        api_check_state.attach_params({'id': param['id']})

        return self._make_api_call_with_err_handling(api_check_state, 'Getting sample status failed.')

    def _check_status(self, param):
        self.save_progress(PAYLOAD_SECURITY_MSG_QUERYING)
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            api_check_state = self._check_status_partial(param)
        except VxError as exc:
            action_result.set_status(phantom.APP_ERROR, '{}'.format(str(exc)))
            return action_result.get_status()

        api_response_json = api_check_state.get_response_json()
        api_response_json['sample_url'] = self._build_sample_url(param['id'])
        api_response_json['status'] = api_response_json['state']
        api_response_json['error_msg'] = '' if 'error' not in api_response_json else api_response_json['error']

        action_result.add_data(api_response_json)
        action_result.set_summary(api_response_json)

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully get status of sample with ID: \'{}\''.format(param['id']))

    def _check_url_hash_partial(self, param):
        config = self.get_config()
        api_object = ApiSubmitHashForUrl(config[PAYLOAD_SECURITY_API_KEY], self._base_url, self)
        api_object.attach_data(param)

        self._make_api_call_with_err_handling(api_object, 'Getting url hash failed.')

        return api_object.get_response_json()

    def _check_url_hash(self, param):
        self.save_progress(PAYLOAD_SECURITY_MSG_QUERYING)
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            api_response_json = self._check_url_hash_partial(param)
        except VxError as exc:
            action_result.set_status(phantom.APP_ERROR, '{}'.format(str(exc)))
            return action_result.get_status()

        action_result.add_data(api_response_json)

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully get hash of url: \'{}\''.format(param['url']))

    def _get_pcap(self, param):
        param.update({'file_type': 'pcap'})

        return self._get_file(param)

    def _get_file(self, param):
        config = self.get_config()
        api_result_object = ApiReportFile(config[PAYLOAD_SECURITY_API_KEY], self._base_url, self)
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress(PAYLOAD_SECURITY_MSG_QUERYING)
        api_result_object.attach_params({'id': param['id'], 'type': param['file_type']})

        try:
            self._make_api_call_with_err_handling(api_result_object, 'Getting file failed.')
        except VxError as exc:
            action_result.set_status(phantom.APP_ERROR, '{}'.format(str(exc)))
            return action_result.get_status()

        api_response = api_result_object.get_api_response()
        data = self._save_file_to_vault(action_result, api_response, api_response.headers['Vx-Filename'], param['id'], param['file_type'])
        data['sample_url'] = self._build_sample_url(param['id'])

        action_result.add_data(data)
        action_result.set_summary(data)

        return action_result.get_status()

    def _get_file_from_url(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        disassembled = urlparse(param['url'])
        filename, file_ext = splitext(basename(disassembled.path))

        guid = uuid.uuid4()
        local_dir = '/vault/tmp/{}'.format(guid)
        self.save_progress("Using temp directory: {0}".format(guid))

        try:
            os.makedirs(local_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to create temporary folder '/vault/tmp'.", e)

        f_out_name = local_dir + '/online_file_{}_{}{}'.format(str(time.time()).replace('.', ''), filename, file_ext)

        self.save_progress('Fetching data from given url')
        file_resp = urllib.urlopen(param['url'])
        f_out = open(f_out_name, 'wb')
        f_out.write(file_resp.read())
        f_out.close()

        vault_ret_dict = Vault.add_attachment(f_out_name, self.get_container_id(), file_name=os.path.basename(f_out_name))

        data = {}
        if vault_ret_dict['succeeded']:
            data = {
                'vault_id': vault_ret_dict[phantom.APP_JSON_HASH],
                'file_name': os.path.basename(f_out_name),
                'file_type': file_ext[1:],
            }

            action_result.set_status(phantom.APP_SUCCESS)
        else:
            action_result.set_status(phantom.APP_ERROR, phantom.APP_ERR_FILE_ADD_TO_VAULT)
            action_result.append_to_message(vault_ret_dict['message'])

        shutil.rmtree(local_dir)

        action_result.add_data(data)
        action_result.set_summary(data)

        return action_result.get_status()

    def _save_file(self, directory, file_content, filename, suffix):
        retrieved_filename_without_gz_ext, retrieved_file_extension = os.path.splitext(filename)

        new_file_name = retrieved_filename_without_gz_ext if retrieved_file_extension == '.gz' else filename  # As we want to unpack it, put filename without '.gz. extension
        f_out_name = directory + '/Falcon_{}_{}_{}'.format(str(time.time()).replace('.', ''), suffix.replace(':', '_'), new_file_name)
        if retrieved_file_extension == '.gz':
            f_out = open(f_out_name, 'wb')
            try:
                gzip_file_handle = gzip.GzipFile(fileobj=BytesIO(file_content))
                f_out.write(gzip_file_handle.read())
            except Exception as e:
                f_out_name += retrieved_file_extension
                f_out = open(f_out_name, 'wb')
                f_out.write(file_content)
                f_out.close()
            f_out.close()
        else:
            f_out = open(f_out_name, 'wb')
            f_out.write(file_content)
            f_out.close()

        return f_out_name

    def _save_file_to_vault(self, action_result, response, filename, suffix, file_type):
        # Create a tmp directory on the vault partition
        guid = uuid.uuid4()
        local_dir = '/vault/tmp/{}'.format(guid)
        self.save_progress("Using temp directory: {0}".format(guid))

        try:
            os.makedirs(local_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to create temporary folder '/vault/tmp'.", e)

        file_path = self._save_file(local_dir, response.content, filename, suffix)

        # move the file to the vault
        vault_ret_dict = Vault.add_attachment(file_path, self.get_container_id(), file_name=os.path.basename(file_path))

        data = {}
        if vault_ret_dict['succeeded']:
            data = {
                'vault_id': vault_ret_dict[phantom.APP_JSON_HASH],
                'file_name': os.path.basename(file_path),
                'file_type': file_type,
            }

            action_result.set_status(phantom.APP_SUCCESS)
        else:
            action_result.set_status(phantom.APP_ERROR, phantom.APP_ERR_FILE_ADD_TO_VAULT)
            action_result.append_to_message(vault_ret_dict['message'])

        shutil.rmtree(local_dir)

        return data

    def _get_report_partial(self, param):
        config = self.get_config()
        api_summary_object = ApiReportSummary(config[PAYLOAD_SECURITY_API_KEY], self._base_url, self)
        api_summary_object.attach_params(param)

        self._make_api_call_with_err_handling(api_summary_object, 'Getting report failed.')

        api_response_json = api_summary_object.get_response_json()
        api_response_json['sample_url'] = self._build_sample_url(param['id'])
        verdict_label_map = {
            'malicious': 'danger',
            'suspicious': 'warning',
            'no specific threat': 'success',
            'whitelisted': 'info',
            'no verdict': 'default'
        }
        if api_response_json['verdict']:
            api_response_json['verdict_label'] = verdict_label_map[api_response_json['verdict']]

        return {'api_object': api_summary_object, 'prepared_json_response': api_response_json}

    def _get_report(self, param):
        self.save_progress(PAYLOAD_SECURITY_MSG_QUERYING)
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            partial_results = self._get_report_partial(param)
            api_response_json = partial_results['prepared_json_response']

        except VxError as exc:
            action_result.set_status(phantom.APP_ERROR, '{}'.format(str(exc)))
            return action_result.get_status()

        action_result.add_data(api_response_json)

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully get summary of sample with Id: \'{}\''.format(param['id']))

    def _detonation_partial(self, param, detonation_api_object):
        api_response_json = detonation_api_object.get_response_json()

        if 'sha256' not in api_response_json:
            return VxError("Hash not found in API response. Please check spawn.log.")

        sample_sha_256 = api_response_json['sha256']

        sample_env_id = param['environment_id']
        sample_id = '{}:{}'.format(sample_sha_256, sample_env_id)
        sample_params = {
            'id': sample_id
        }
        final_check_status_response = None
        start_time_of_checking = time.time()

        self.save_progress('Successfully submitted chosen element for detonation. Waiting {} seconds to do status checking...'.format(PAYLOAD_SECURITY_DETONATION_QUEUE_TIME_INTERVAL_SECONDS))
        for x in range(0, PAYLOAD_SECURITY_DETONATION_QUEUE_NUMBER_OF_ATTEMPTS):
            self.debug_print('detonate_debug_print_queue', 'Starting iteration {} of {}. Sleep time is {}.'.format(x, PAYLOAD_SECURITY_DETONATION_QUEUE_NUMBER_OF_ATTEMPTS,
                                                                                                                       PAYLOAD_SECURITY_DETONATION_QUEUE_TIME_INTERVAL_SECONDS))
            time.sleep(PAYLOAD_SECURITY_DETONATION_QUEUE_TIME_INTERVAL_SECONDS)
            api_check_state = self._check_status_partial(sample_params)
            api_response_json = api_check_state.get_response_json()
            final_check_status_response = api_response_json

            if api_response_json['state'] == PAYLOAD_SECURITY_SAMPLE_STATE_IN_PROGRESS:
                self.save_progress('Submitted element is processed. Waiting {} seconds to do status checking...'.format(PAYLOAD_SECURITY_DETONATION_PROGRESS_TIME_INTERVAL_SECONDS))
                for y in range(0, PAYLOAD_SECURITY_DETONATION_PROGRESS_NUMBER_OF_ATTEMPTS):
                    self.debug_print('detonate_debug_print_progress', 'Starting iteration {} of {}. Sleep time is {}.'.format(y, PAYLOAD_SECURITY_DETONATION_PROGRESS_NUMBER_OF_ATTEMPTS,
                                                                                                                                  PAYLOAD_SECURITY_DETONATION_PROGRESS_TIME_INTERVAL_SECONDS))
                    time.sleep(PAYLOAD_SECURITY_DETONATION_PROGRESS_TIME_INTERVAL_SECONDS)
                    api_check_state = self._check_status_partial(sample_params)
                    api_response_json = api_check_state.get_response_json()
                    final_check_status_response = api_response_json
                    self.save_progress(
                        PAYLOAD_SECURITY_MSG_CHECKED_STATE.format(api_response_json['state'], datetime.now().strftime("%Y-%m-%d %H:%M:%S"), y + 1,
                                                                  PAYLOAD_SECURITY_DETONATION_PROGRESS_NUMBER_OF_ATTEMPTS,
                                                                  PAYLOAD_SECURITY_DETONATION_PROGRESS_TIME_INTERVAL_SECONDS))

                    if api_response_json['state'] in [PAYLOAD_SECURITY_SAMPLE_STATE_SUCCESS, PAYLOAD_SECURITY_SAMPLE_STATE_ERROR]:
                        self.debug_print('detonate_debug_print_progress_result_status',
                                         'Got state \'{}\' from \'{}\' state after \'{}\' seconds of work.'.format(api_response_json['state'], PAYLOAD_SECURITY_SAMPLE_STATE_IN_PROGRESS,
                                                                                                                   (time.time() - start_time_of_checking)))
                        break
                else:  # 'else' is ran, when iteration was not broken. When it has happen, break also the outer loop.
                    continue
                break
            elif api_response_json['state'] == PAYLOAD_SECURITY_SAMPLE_STATE_ERROR:
                self.debug_print('detonate_debug_print_queue_result_status',
                                 'Got state \'{}\' from \'{}\' state after \'{}\' seconds of work.'.format(PAYLOAD_SECURITY_SAMPLE_STATE_ERROR, PAYLOAD_SECURITY_SAMPLE_STATE_IN_QUEUE,
                                                                                                           (time.time() - start_time_of_checking)))
                break
            elif api_response_json['state'] == PAYLOAD_SECURITY_SAMPLE_STATE_SUCCESS:
                break
            else:
                self.save_progress(
                    PAYLOAD_SECURITY_MSG_CHECKED_STATE.format(api_response_json['state'], datetime.now().strftime("%Y-%m-%d %H:%M:%S"), x + 1, PAYLOAD_SECURITY_DETONATION_QUEUE_NUMBER_OF_ATTEMPTS,
                                                              PAYLOAD_SECURITY_DETONATION_QUEUE_TIME_INTERVAL_SECONDS))

        if final_check_status_response['state'] in [PAYLOAD_SECURITY_SAMPLE_STATE_IN_QUEUE, PAYLOAD_SECURITY_SAMPLE_STATE_IN_PROGRESS]:
            raise VxError('Action reached the analysis timeout. Last state is \'{}\'. You can still observe the state using \'check status\' action and after successful analysis, retrieve results by \'get report\' action.'.format(final_check_status_response['state']))
        elif final_check_status_response['state'] == PAYLOAD_SECURITY_SAMPLE_STATE_ERROR:
            raise VxError('During the analysis, error has occurred: \'{}\'. For more possible information, please visit sample page({}) and/or Hybrid Analysis Knowledge Base.'.format(
                                         final_check_status_response['error'], self._build_sample_url(sample_id)))
        else:
            self.save_progress(PAYLOAD_SECURITY_MSG_DETONATION_QUERYING_REPORT)
            partial_results = self._get_report_partial({'id': sample_id})
            return partial_results['prepared_json_response']

    def _detonate_url(self, param):
        config = self.get_config()
        api_submit_file_object = ApiSubmitUrlForAnalysis(config[PAYLOAD_SECURITY_API_KEY], self._base_url, self)
        self.save_progress(PAYLOAD_SECURITY_MSG_SUBMITTING_FILE)

        action_result = self.add_action_result(ActionResult(dict(param)))
        api_submit_file_object.attach_data(param)

        try:
            self._make_api_call_with_err_handling(api_submit_file_object, 'URL submit failed.')
            report_api_json_response = self._detonation_partial(param, api_submit_file_object)
        except VxError as exc:
            action_result.set_status(phantom.APP_ERROR, '{}'.format(str(exc)))
            return action_result.get_status()

        action_result.add_data(report_api_json_response)

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully submitted URL and retrieved analysis result. Sample sha256: \'{}\' and environment ID: \'{}\''.format(report_api_json_response['sha256'], param['environment_id']))

    def _detonate_file(self, param):
        config = self.get_config()
        api_submit_file_object = ApiSubmitFile(config[PAYLOAD_SECURITY_API_KEY], self._base_url, self)
        self.save_progress(PAYLOAD_SECURITY_MSG_SUBMITTING_FILE)

        action_result = self.add_action_result(ActionResult(dict(param)))
        return_value, files = self._get_file_dict(param, action_result)

        if phantom.is_fail(return_value):
            return action_result.get_status()

        api_submit_file_object.attach_files(files)
        api_submit_file_object.attach_data({'environment_id': param['environment_id']})

        try:
            self._make_api_call_with_err_handling(api_submit_file_object, 'File submit failed.')
            report_api_json_response = self._detonation_partial(param, api_submit_file_object)
        except VxError as exc:
            action_result.set_status(phantom.APP_ERROR, '{}'.format(str(exc)))
            return action_result.get_status()

        action_result.add_data(report_api_json_response)

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully submitted file and retrieved analysis result. Sample sha256: \'{}\' and environment ID: \'{}\''.format(report_api_json_response['sha256'], param['environment_id']))

    def _detonate_online_file(self, param):
        config = self.get_config()
        api_submit_file_object = ApiSubmitOnlineFile(config[PAYLOAD_SECURITY_API_KEY], self._base_url, self)
        self.save_progress(PAYLOAD_SECURITY_MSG_SUBMITTING_FILE)

        action_result = self.add_action_result(ActionResult(dict(param)))
        api_submit_file_object.attach_data(param)

        try:
            self._make_api_call_with_err_handling(api_submit_file_object, 'Online file submit failed.')
            report_api_json_response = self._detonation_partial(param, api_submit_file_object)
        except VxError as exc:
            action_result.set_status(phantom.APP_ERROR, '{}'.format(str(exc)))
            return action_result.get_status()

        action_result.add_data(report_api_json_response)

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully submitted file and retrieved analysis result. Sample sha256: \'{}\' and environment ID: \'{}\''.format(report_api_json_response['sha256'], param['environment_id']))

    def _convert_verdict_name_to_key(self, verdict_name):
        return verdict_name.replace(' ', '_')

    def _hunt_similar(self, param):
        return self._search_terms({'similar_to': param['sha256']})

    def _hunt_file(self, param):
        return self._search_terms(param)

    def _hunt_hash(self, param, action_result=None):
        if action_result is None:
            action_result = self.add_action_result(ActionResult(dict(param)))

        config = self.get_config()
        api_search_object = ApiSearchHash(config[PAYLOAD_SECURITY_API_KEY], self._base_url, self)
        api_search_object.attach_data(param)

        return self._partial_search(param, api_search_object, action_result)

    def _hunt_malware_family(self, param):
        return self._search_terms({'vx_family': param['malware_family']})

    def _hunt_domain(self, param):
        return self._search_terms(param)

    def _hunt_url(self, param):
        self.save_progress('Checking url hash in Falcon Sandbox')
        action_result = self.add_action_result(ActionResult(dict(param)))

        params_for_searching = {}
        try:
            params_for_searching['hash'] = self._check_url_hash_partial(param)['sha256']
        except VxError as exc:
            action_result.set_status(phantom.APP_ERROR, '{}'.format(str(exc)))
            return action_result.get_status()

        return self._hunt_hash(params_for_searching, action_result)

    def _hunt_ip(self, param):
        return self._search_terms(param)

    def _search_terms(self, param):
        config = self.get_config()
        action_result = self.add_action_result(ActionResult(dict(param)))
        api_search_object = ApiSearchTerms(config[PAYLOAD_SECURITY_API_KEY], self._base_url, self)
        api_search_object.attach_data(param)

        return self._partial_search(param, api_search_object, action_result)

    def _partial_search(self, param, api_object, action_result):
        self.save_progress('Searching data in Falcon Sandbox')
        try:
            self._make_api_call_with_err_handling(api_object, 'Searched failed.')
        except VxError as exc:
            action_result.set_status(phantom.APP_ERROR, '{}'.format(str(exc)))
            return action_result.get_status()

        verdict_summary = dict.fromkeys([self._convert_verdict_name_to_key(verdict_name) for verdict_name in PAYLOAD_SECURITY_SAMPLE_VERDICT_NAMES], 0)
        api_response_json = api_object.get_response_json()
        data = api_response_json if 'hash' in param else api_response_json['result']

        for search_row in data:
            verdict_summary[self._convert_verdict_name_to_key(search_row['verdict'])] += 1
            environment = None
            threatscore_verbose = None

            if search_row['environment_description'] is not None:
                environment = search_row['environment_description']

            if search_row['environment_id'] is not None:
                if environment is not None:
                    environment = '{} ({})'.format(environment, search_row['environment_id'])
                else:
                    environment = '{}'.format(search_row['environment_id'])

            if search_row['threat_score'] is not None:
                threatscore_verbose = str(search_row['threat_score']) + '/100'

            search_row['environment'] = environment
            search_row['threat_score_verbose'] = threatscore_verbose

            action_result.add_data(search_row)

        summary = {
            'found': len(data),
            'found_by_verdict_name': verdict_summary
        }

        action_result.set_summary(summary)

        return action_result.set_status(phantom.APP_SUCCESS, 'Found {} matching samples'.format(summary['found']))

    def _test_connectivity(self):
        config = self.get_config()
        api_api_key_data_object = ApiKeyCurrent(config[PAYLOAD_SECURITY_API_KEY], self._base_url, self)
        self.save_progress(PAYLOAD_SECURITY_MSG_QUERYING)
        try:
            self._make_api_call(api_api_key_data_object)
        except requests.exceptions.RequestException as exc:
            self.save_progress('Connection to server failed. Error: \'{}\''.format(str(exc)))
            self.set_status(phantom.APP_ERROR, 'Connectivity test failed')
            return self.get_status()
        except ValueError as exc:
            self.save_progress('Connection to server failed. It\'s highly possible that given base URL is invalid. Please re-check it and try again.')
            self.set_status(phantom.APP_ERROR, 'Connectivity test failed')
            return self.get_status()

        if api_api_key_data_object.if_request_success() is False:
            self.save_progress(api_api_key_data_object.get_prepared_response_msg())
            self.set_status(phantom.APP_ERROR, 'Connectivity test failed')
            return self.get_status()

        api_json_response = api_api_key_data_object.get_response_json()

        if int(api_json_response['auth_level']) < 100:
            self.save_progress('You are using API Key with \'{}\' privileges. Some of actions can not work, as they need at least \'default\' privileges. To obtain proper key, please contact with support@hybrid-analysis.com.'.format(api_json_response['auth_level_name']))

        self.save_progress(api_api_key_data_object.get_prepared_response_msg())

        return self.set_status_save_progress(phantom.APP_SUCCESS, 'Connectivity test passed')

    def handle_action(self, param):

        return_value = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this connector run
        action_id = self.get_action_identifier()

        self.debug_print('action_id', action_id)

        if action_id == self.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            return_value = self._test_connectivity()
        elif action_id == self.ACTION_ID_DETONATE_FILE:
            return_value = self._detonate_file(param)
        elif action_id == self.ACTION_ID_DETONATE_ONLINE_FILE:
            return_value = self._detonate_online_file(param)
        elif action_id == self.ACTION_ID_DETONATE_URL:
            return_value = self._detonate_url(param)
        elif action_id == self.ACTION_ID_GET_REPORT:
            return_value = self._get_report(param)
        elif action_id == self.ACTION_ID_GET_FILE:
            return_value = self._get_file(param)
        elif action_id == self.ACTION_ID_GET_PCAP:
            return_value = self._get_pcap(param)
        elif action_id == self.ACTION_ID_SEARCH_TERMS:
            return_value = self._search_terms(param)
        elif action_id == self.ACTION_ID_HUNT_FILE:
            return_value = self._hunt_file(param)
        elif action_id == self.ACTION_ID_HUNT_HASH:
            return_value = self._hunt_hash(param)
        elif action_id == self.ACTION_ID_HUNT_IP:
            return_value = self._hunt_ip(param)
        elif action_id == self.ACTION_ID_HUNT_URL:
            return_value = self._hunt_url(param)
        elif action_id == self.ACTION_ID_HUNT_DOMAIN:
            return_value = self._hunt_domain(param)
        elif action_id == self.ACTION_ID_HUNT_MALWARE_FAMILY:
            return_value = self._hunt_malware_family(param)
        elif action_id == self.ACTION_ID_HUNT_SIMILAR:
            return_value = self._hunt_similar(param)
        elif action_id == self.ACTION_ID_CHECK_STATUS:
            return_value = self._check_status(param)
        elif action_id == self.ACTION_ID_GET_FILE_FROM_URL:
            return_value = self._get_file_from_url(param)
        elif action_id == self.ACTION_ID_CHECK_URL_HASH:
            return_value = self._check_url_hash(param)

        return return_value


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

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get(phantom.BaseConnector._get_phantom_base_url() + "login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = phantom.BaseConnector._get_phantom_base_url() + 'login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post(phantom.BaseConnector._get_phantom_base_url() + "login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = VxStreamConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
