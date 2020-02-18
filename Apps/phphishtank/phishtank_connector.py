# File: phishtank_connector.py
# Copyright (c) 2016-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Local imports
import phishtank_consts

# Global imports
import simplejson as json
import requests
import time


class PhishtankConnector(BaseConnector):
    ACTION_ID_WHOIS_DOMAIN = 'check_url'

    def __init__(self):
        super(PhishtankConnector, self).__init__()

    def handle_action(self, param):
        result = None
        action_id = self.get_action_identifier()
        if action_id == self.ACTION_ID_WHOIS_DOMAIN:
            result = self.check_url(param)
        elif action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            result = self.test_asset_connectivity(param)
        return result

    def test_asset_connectivity(self, param):
        config = self.get_config()
        app_key = config.get('apikey', None)
        self.save_progress(phishtank_consts.PHISHTANK_MSG_CONNECTING)
        time.sleep(10)
        try:
            if app_key:
                api_params = {'url': 'https://www.google.com',
                          'format': 'json',
                          phishtank_consts.PHISHTANK_APP_KEY: app_key}
            else:
                api_params = {'url': 'https://www.google.com',
                          'format': 'json'}
            response_code = requests.post(
                 phishtank_consts.PHISHTANK_API_DOMAIN,
                 data=api_params).status_code
        except Exception as e:
            self.debug_print('test_asset_connectivity: ', e)
            self.set_status(
                 phantom.APP_ERROR,
                 phishtank_consts.PHISHTANK_ERR_CONNECTIVITY_TEST, e)
            self.append_to_message(
                 phishtank_consts.PHISHTANK_MSG_CHECK_CONNECTIVITY)
            return self.get_status()

        if response_code == 200:
            return self.set_status_save_progress(
                 phantom.APP_SUCCESS,
                 phishtank_consts.PHISHTANK_SUCC_CONNECTIVITY_TEST)
        else:
            self.set_status(phantom.APP_ERROR,
                            phishtank_consts.
                            PHISHTANK_SERVER_RETURNED_ERROR_CODE.
                            format(code=response_code))
            self.append_to_message(
                 phishtank_consts.PHISHTANK_MSG_CHECK_CONNECTIVITY)
            return self.get_status()

    def check_url(self, param):
        config = self.get_config()
        app_key = config.get('apikey', None)
        action_result = self.add_action_result(ActionResult(dict(param)))
        summary = action_result.update_summary({})
        if param is None or param['url'] is None:
            self.debug_print('Mandatory action parameters missing')
            action_result.set_status(phantom.APP_ERROR,
                                     phishtank_consts.
                                     PHISHTANK_ERR_MSG_ACTION_PARAM)
            return action_result.get_status()
        else:
            if app_key:
                api_params = {'url': param['url'],
                          'format': 'json',
                          phishtank_consts.PHISHTANK_APP_KEY: app_key}
            else:
                api_params = {'url': param['url'],
                          'format': 'json'}
            self.save_progress(phishtank_consts.PHISHTANK_MSG_QUERY_URL,
                               query_url=param['url'])
            try:
                query_res = requests.post(phishtank_consts.
                                          PHISHTANK_API_DOMAIN,
                                          data=api_params)
            except Exception as e:
                self.debug_print('check_url: ', e)
                action_result.set_status(phantom.APP_ERROR,
                                         phishtank_consts.
                                         PHISHTANK_SERVER_CONNECTION_ERROR, e)
                return action_result.get_status()

            action_result.add_debug_data({'response_text': query_res.text
                                          if query_res else ''})
            self.debug_print('status_code', query_res.status_code)
            if query_res.status_code == 509:
                return action_result.set_status(
                                         phantom.APP_ERROR,
                                         phishtank_consts.
                                         PHISHTANK_SERVER_ERROR_RATE_LIMIT)
            if query_res.status_code != 200:
                return action_result.set_status(
                                         phantom.APP_ERROR,
                                         phishtank_consts.
                                         PHISHTANK_SERVER_RETURNED_ERROR_CODE.
                                         format(code=query_res.status_code))
            try:
                result = query_res.json()
            except Exception as e:
                self.debug_print('Response from server not a valid JSON', e)
                return action_result.set_status(
                                         phantom.APP_ERROR,
                                         'Response from server not' + ' a valid JSON')

            if 'results' in result:
                status = result['results']
                action_result.append_to_message(
                    phishtank_consts.PHISHTANK_SERVICE_SUCC_MSG)
            else:
                action_result.set_status(
                    phantom.APP_ERROR,
                    phishtank_consts.PHISHTANK_ERR_MSG_OBJECT_QUERIED)
                return action_result.get_status()
            try:
                status_summary = {}
                if status['in_database'] is True:
                    status_summary['Verified'] = status["verified"]
                    status_summary['In_Database'] = status["in_database"]
                    status_summary['Valid'] = status["valid"]
                else:
                    if 'phish_detail_page' not in status.keys():
                        status["phish_detail_page"] = None
                    if 'verified_at' not in status.keys():
                        status["verified_at"] = None
                    if 'phish_id' not in status.keys():
                        status["phish_id"] = None
                    if 'valid' not in status.keys():
                        status["valid"] = None
                    if 'verified' not in status.keys():
                        status["verified"] = None

                    status_summary['Verified'] = status["verified"]
                    status_summary['In_Database'] = status["in_database"]
                    status_summary['Valid'] = status["valid"]
                summary.update(status_summary)
            except Exception as e:
                action_result.set_status(phantom.APP_ERROR, 'Error populating summary', e)
                return action_result.get_status()

            action_result.add_data(status)
            action_result.set_status(phantom.APP_SUCCESS)
            return phantom.APP_SUCCESS


if __name__ == '__main__':
    import sys
    import pudb
    pudb.set_trace()
    if len(sys.argv) < 2:
        print('No test json specified as input')
        exit(0)
    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = PhishtankConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))
    exit(0)
