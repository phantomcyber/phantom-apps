# File: airwatch_connector.py
#
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

import phantom.app as phantom
import json
import requests
from phantom.action_result import ActionResult
from bs4 import UnicodeDammit


class AirWatchConnector(phantom.BaseConnector):
    ACTION_ID_TEST = 'test_asset_connectivity'
    ACTION_ID_ADD = 'add_to_group'

    def __init__(self):
        super(AirWatchConnector, self).__init__()

    def _get_headers(self):
        self.save_progress('_get_headers()')
        config = self.get_config()
        tenant = config['tenant']
        headers = {}
        headers['aw-tenant-code'] = tenant
        headers['Accept'] = "application/json;version=2"
        headers['Content-Type'] = "application/json"
        return headers

    def _build_groupadd_body(self, param):
        self.save_progress('_build_groupadd_body()')
        body = '[{{"value": "{0}","path": "/smartGroupsOperationV2/devices","op": "add"}}]'.format(UnicodeDammit(param.get('device_uuid')).unicode_markup.encode('utf-8'))
        return body

    def _build_groupadd_url(self, param):
        self.save_progress('_build_groupadd_url()')
        config = self.get_config()
        url = '{0}/mdm/smartgroups/{1}'.format(
            UnicodeDammit(config['base_url']).unicode_markup.encode('utf-8'),
            UnicodeDammit(param.get('smartgroup_uuid')).unicode_markup.encode('utf-8'))
        return url

    def _add_to_group(self, param):
        self.save_progress('_add_to_group()')
        action_result = self.add_action_result(ActionResult(dict(param)))
        try:
            config = self.get_config()
            u = UnicodeDammit(config['username']).unicode_markup.encode('utf-8')
            p = config['password']
            headers = self._get_headers()
            body = self._build_groupadd_body(param)
            self.save_progress("Body: {}".format(body))
            url = self._build_groupadd_url(param)
            self.save_progress("URL: {}".format(url))
            try:
                response = requests.patch(url, data=body, headers=headers, auth=(u, p), verify=False)
            except requests.exceptions.InvalidSchema:
                error_message = 'Error connecting to server. No connection adapters were found for %s' % (url)
                return action_result.set_status(phantom.APP_ERROR, error_message)
            self.save_progress("Status code: {}".format(response.status_code))
            json_response = json.loads(response.text)
            if response.status_code >= 200 and response.status_code < 300 and UnicodeDammit(param.get('device_uuid')).unicode_markup.encode('utf-8') in json_response['devices']:
                self.save_progress('Device ({0}) successfully added to smartgroup ({1})'.format(
                    UnicodeDammit(param.get('device_uuid').unicode_markup.encode('utf-8')),
                    UnicodeDammit(param.get('smartgroup_uuid')).unicode_markup.encode('utf-8')))
                return action_result.set_status(phantom.APP_SUCCESS, 'Successfully added device to group')
            else:
                self.save_progress('Failed to add device to group. Response: {0}'.format(response.status_code))
                return action_result.set_status(phantom.APP_ERROR, 'Failed to add device to group. Response: {0}'.format(response.status_code))

        except Exception as e:
            self.save_progress("Error occurred. {}".format(e))
            self.save_progress('Exception thrown while adding to group')
            return action_result.set_status(phantom.APP_ERROR, "Error occurred. {}".format(e))

    def _test_connectivity(self, param):
        self.save_progress('Nothing to test...')
        self.save_progress('Hopefully it works for real')
        return self.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        action = self.get_action_identifier()
        ret_val = phantom.APP_SUCCESS
        if action == self.ACTION_ID_ADD:
            ret_val = self._add_to_group(param)
        elif action == self.ACTION_ID_TEST:
            ret_val = self._test_connectivity(param)
        return ret_val


if __name__ == '__main__':
    import sys
    import pudb
    pudb.set_trace()
    if len(sys.argv) < 2:
        print 'No test json specified as input'
        exit(0)
    with open(sys.argv[1]) as (f):
        in_json = f.read()
        in_json = json.loads(in_json)
        print json.dumps(in_json, indent=4)
        connector = AirWatchConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print json.dumps(json.loads(ret_val), indent=4)
    exit(0)
