# File: ssmachine_connector.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# --

# Phantom App imports
from ssmachine_consts import *
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault as Vault
import phantom.rules as ph_rules

# Imports local to this App
import os
import uuid
import requests
import hashlib
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class SsmachineConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(SsmachineConnector, self).__init__()
        self._headers = None

    def initialize(self):

        config = self.get_config()

        self._api_key = config.get("ssmachine_key")
        self._api_phrase = config.get("ssmachine_hash")
        self._rest_url = "{0}".format(SSMACHINE_JSON_DOMAIN)
        return phantom.APP_SUCCESS

    def _process_html_response(self, response, action_result):

        # An html response, is bound to be an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _parse_response(self, result, r):

        # It's ok if r.text is None, dump that, if the result object supports recording it
        if hasattr(result, 'add_debug_data'):
            result.add_debug_data({'r_status_code': r.status_code})
            result.add_debug_data({'r_text': r.text })
            result.add_debug_data({'r_headers': r.headers})

        if "X-Screenshotmachine-Response" in list(r.headers.keys()):
            return RetVal(result.set_status(phantom.APP_ERROR, "Screenshot Machine Returned an error: {0}".format(r.headers["X-Screenshotmachine-Response"])), None)

        if ('html' in r.headers.get('Content-Type', '')):
            return self._process_html_response(r, result)

        """
        if 'image' not in r.headers.get('content-type'):
            return (result.set_status(phantom.APP_ERROR,
                        "Unable to parse response as an image, status_code: {0}, data: {1}".format(r.status_code, r.content)),
                        r.status_code, r.headers.get('content-type'), r.content)
                        """

        if not (200 <= r.status_code < 300):
            message = r.text.replace('{', '{{').replace('}', '}}')
            return RetVal(result.set_status(phantom.APP_ERROR, "Call returned error, status_code: {0}, data: {1}".format(r.status_code, message)), None)

        if ('image' not in r.headers.get('Content-Type', '')):
            message = r.text.replace('{', '{{').replace('}', '}}')
            return RetVal(result.set_status(phantom.APP_ERROR, "Response does not contain an image. status_code: {0}, data: {1}".format(r.status_code, message)), None)

        # Things look fine
        return RetVal(phantom.APP_SUCCESS, r.content)

    def _make_rest_call(self, endpoint, result, params={}, headers={}, json=None, method="get", stream=False):

        url = "{0}{1}".format(self._rest_url, endpoint)

        if self._headers is not None:
            (headers.update(self._headers))

        request_func = getattr(requests, method)

        if not request_func:
            return result.set_status(phantom.APP_ERROR, "Invalid method call: {0} for requests module".format(method)), None

        try:
            r = request_func(url, headers=headers, params=params, json=json, stream=stream, verify=True)
        except Exception as e:
            return result.set_status(phantom.APP_ERROR, "REST Api to server failed", e), None

        ret_val, resp_data = self._parse_response(result, r)

        # Any http or parsing error is handled by the _parse_response function
        if phantom.is_fail(ret_val):
            return (result.get_status(), resp_data)

        return (phantom.APP_SUCCESS, resp_data)

    def _test_connectivity(self):

        params = dict()
        params['url'] = "https://www.screenshotmachine.com"
        self.save_progress("Checking to see if Screenshotmachine.com is online...")

        params['key'] = self._api_key

        # Check if we have a Secret Phrase
        if self._api_phrase is None:
            params['hash'] = ""
        else:
            params['hash'] = str(hashlib.md5((params['url'] + self._api_phrase).encode('utf-8')).hexdigest())

        params['cacheLimit'] = '0'
        ret_val, resp_data = self._make_rest_call('', self, params, method='post', stream=True)

        if (phantom.is_fail(ret_val)):
            self.append_to_message('Test connectivity failed')
            return self.get_status()

        return self.set_status_save_progress(ret_val, "Test Connectivity Passed")

    def _handle_post_url(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        params = dict()
        params['url'] = param["url"]
        params['key'] = self._api_key

        # Check if we have a size
        sizes = {"tiny": "T", "small": "S", "normal": "N", "medium": "M", "large": "L", "full page": "F"}
        test = param.get("size")
        if not test:
            self.save_progress("Size was blank, using the default \"full page\" size.")
            test = "full page"
        if not sizes.get(test.lower()):
            self.save_progress("Given size not found, using the default \"full page\" size.")
            params['size'] = "F"
        else:
            params['size'] = sizes[test.lower()]

        # Check if we have a Secret Phrase
        if self._api_phrase is None:
            params['hash'] = ""
        else:
            params['hash'] = str(hashlib.md5((params['url'] + self._api_phrase).encode('utf-8')).hexdigest())

        params['cacheLimit'] = '0'
        params['format'] = 'JPG'
        params['timeout'] = '200'

        ret_val, image = self._make_rest_call('', action_result, params, method='post', stream=True)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        permalink = None
        # only create a permalink if the hash is used
        if params['hash']:
            permalink = self._get_sspermalink('', params=params, method='post')

        file_name = param["url"] + "_screenshot.jpg"

        if hasattr(Vault, "create_attachment"):
            vault_ret = Vault.create_attachment(image, self.get_container_id(), file_name=file_name)
        else:
            if hasattr(Vault, 'get_vault_tmp_dir'):
                temp_dir = Vault.get_vault_tmp_dir()
            else:
                temp_dir = '/opt/phantom/vault/tmp'
            temp_dir = temp_dir + '/{}'.format(uuid.uuid4())
            os.makedirs(temp_dir)
            file_path = os.path.join(temp_dir, 'tempimage.jpg')

            with open(file_path, 'wb') as f:
                f.write(image)

            vault_ret = Vault.add_attachment(file_path, self.get_container_id(), file_name=file_name)

        if vault_ret.get('succeeded'):
            action_result.set_status(phantom.APP_SUCCESS, "Downloaded screenshot")
            _, _, vault_meta_info = ph_rules.vault_info(container_id=self.get_container_id(), vault_id=vault_ret[phantom.APP_JSON_HASH])
            if (not vault_meta_info):
                self.debug_print("Error while fetching meta information for vault ID: {}".format(vault_ret[phantom.APP_JSON_HASH]))
                return action_result.set_status(phantom.APP_ERROR, "Could not find specified vault ID in vault")

            vault_path = vault_meta_info[0]['path']
            summary = {
                    phantom.APP_JSON_VAULT_ID: vault_ret[phantom.APP_JSON_HASH],
                    phantom.APP_JSON_NAME: file_name,
                    'vault_file_path': vault_path,
                    phantom.APP_JSON_SIZE: vault_ret.get(phantom.APP_JSON_SIZE)}
            if permalink:
                summary['permalink'] = permalink
            action_result.update_summary(summary)

        return action_result.get_status()

    def _get_sspermalink(self, endpoint, params, method='get'):
        method = method.upper()
        url = "{0}{1}".format(self._rest_url, endpoint)
        # allow the permalink to retrieve from cache
        params.pop('cacheLimit', None)
        req = requests.Request(method=method, url=url, params=params)
        r = req.prepare()
        return r.url

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if (action_id == "get_screenshot"):
            ret_val = self._handle_post_url(param)
        elif (action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity()

        return ret_val


if __name__ == '__main__':

    import sys
    import pudb
    import argparse
    import json

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
            r = requests.get(BaseConnector._get_phantom_base_url() + "login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = BaseConnector._get_phantom_base_url() + 'login'

            print("Logging into Platform to get the session id")
            r2 = requests.post(BaseConnector._get_phantom_base_url() + "login", verify=False, data=data, headers=headers)
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

        connector = SsmachineConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
