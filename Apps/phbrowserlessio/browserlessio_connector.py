#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

# Usage of the consts file is recommended
# from browserlessio_consts import *
import requests
import json
import os
import hashlib


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class BrowserlessIoConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(BrowserlessIoConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_response(self, r, action_result):
        if r.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_file_response(self, r, action_result):
        # An html response, treat it like an error
        status_code = r.status_code
        if 200 <= status_code < 399:
            # Send contents to Function
            return RetVal(action_result.set_status(phantom.APP_SUCCESS), r.content)
        return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to extract files"), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_file_response(r, action_result)

        if 'image' in r.headers.get('Content-Type', ''):
            return self._process_file_response(r, action_result)

        if 'pdf' in r.headers.get('Content-Type', ''):
            return self._process_file_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="post", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()
        params = dict()
        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self._rest_url + endpoint
        if self._rest_token:
            params['token'] = self._rest_token

        try:
            r = request_func(
                url,
                params=params,
                verify=config.get('verify_server_cert', False),
                headers={'Content-Type': 'application/json'},
                **kwargs
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to endpoint")
        query = '{"url":"https://google.com"}'
        # make rest call
        ret_val, response = self._make_rest_call('/stats', action_result, data=json.dumps(query))

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        if response.status_code == 200:
            # Return success
            self.save_progress("Test Connectivity Passed")
            return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        # return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_get_pdf(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        s_url = param['url']
        headerfooter = param['headerfooter']
        printbackground = param['printbackground']
        landscape = param['landscape']
        followRefresh = param['followRefresh']
        query = {"url": "{}".format(s_url), "options": {
            "displayHeaderFooter": "{}".format(headerfooter),
            "printBackground": "{}".format(printbackground),
            "landscape": "{}".format(landscape)
        }}
        if followRefresh:
            query["gotoOptions"] = {"waitUntil": "networkidle2"}

        # make rest call
        ret_val, response = self._make_rest_call(
            '/pdf', action_result, data=json.dumps(query))

        if phantom.is_fail(ret_val):
            return action_result.get_status()
        else:
            file_name = s_url + "_screenshot.pdf"
            if hasattr(Vault, 'create_attachment'):
                vault_ret = Vault.create_attachment(response, self.get_container_id(), file_name=file_name)
            else:
                if hasattr(Vault, 'get_vault_tmp_dir'):
                    temp_dir = Vault.get_vault_tmp_dir()
                else:
                    temp_dir = '/opt/phantom/vault/tmp'
                temp_dir = temp_dir + ('/{}').format(hashlib.md5(file_name).hexdigest())
                os.makedirs(temp_dir)
                file_path = os.path.join(temp_dir, 'tmpfile')
                with open(file_path, 'wb') as (f):
                    f.write(response)
                vault_ret = Vault.add_attachment(file_path, self.get_container_id(), file_name=file_name)
            if vault_ret.get('succeeded'):
                action_result.set_status(phantom.APP_SUCCESS, 'Downloaded PDF')
                summary = {phantom.APP_JSON_VAULT_ID: vault_ret[phantom.APP_JSON_HASH],
                        phantom.APP_JSON_NAME: file_name,
                        'vault_file_path': Vault.get_file_path(vault_ret[phantom.APP_JSON_HASH]),
                        phantom.APP_JSON_SIZE: vault_ret.get(phantom.APP_JSON_SIZE)}
                action_result.update_summary(summary)
            return action_result.get_status()

    def _handle_get_content(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        s_url = param['url']
        followRefresh = param['followRefresh']

        query = {"url": "{}".format(s_url)}
        if followRefresh:
            query["gotoOptions"] = {"waitUntil": "networkidle2"}
        # make rest call
        ret_val, response = self._make_rest_call(
            '/content', action_result, data=json.dumps(query))

        if phantom.is_fail(ret_val):
            return action_result.get_status()
        else:
            file_name = s_url + "_contents.txt"
            if hasattr(Vault, 'create_attachment'):
                vault_ret = Vault.create_attachment(response, self.get_container_id(), file_name=file_name)
            else:
                if hasattr(Vault, 'get_vault_tmp_dir'):
                    temp_dir = Vault.get_vault_tmp_dir()
                else:
                    temp_dir = '/opt/phantom/vault/tmp'
                temp_dir = temp_dir + ('/{}').format(hashlib.md5(file_name).hexdigest())
                os.makedirs(temp_dir)
                file_path = os.path.join(temp_dir, 'tmpfile')
                with open(file_path, 'wb') as (f):
                    f.write(response)
                vault_ret = Vault.add_attachment(file_path, self.get_container_id(), file_name=file_name)
            if vault_ret.get('succeeded'):
                action_result.set_status(phantom.APP_SUCCESS, 'Downloaded HTML Contents')
                summary = {phantom.APP_JSON_VAULT_ID: vault_ret[phantom.APP_JSON_HASH],
                        phantom.APP_JSON_NAME: file_name,
                        'vault_file_path': Vault.get_file_path(vault_ret[phantom.APP_JSON_HASH]),
                        phantom.APP_JSON_SIZE: vault_ret.get(phantom.APP_JSON_SIZE)}
                action_result.update_summary(summary)
            return action_result.get_status()

    def _handle_get_screenshot(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        s_url = param['url']
        ftype = param['type']
        quality = param['quality']
        fullpage = param['fullpage']
        followRefresh = param['followRefresh']

        jpeg_query = {"url": "{}".format(s_url), "options": {
            "type": "{}".format(ftype),
            "quality": "{}".format(quality),
            "fullPage": "{}".format(fullpage)
        }}
        png_query = {"url": "{}".format(s_url), "options": {
            "type": "{}".format(ftype),
            "fullPage": "{}".format(fullpage)
        }}

        if ftype == "png":
            query = png_query
        else:
            query = jpeg_query
        if followRefresh:
            query["gotoOptions"] = {"waitUntil": "networkidle2"}
        # make rest call
        ret_val, response = self._make_rest_call(
            '/screenshot', action_result, data=json.dumps(query))

        if phantom.is_fail(ret_val):
            return action_result.get_status()
        else:
            file_name = s_url + "_screenshot." + ftype
            if hasattr(Vault, 'create_attachment'):
                vault_ret = Vault.create_attachment(response, self.get_container_id(), file_name=file_name)
            else:
                if hasattr(Vault, 'get_vault_tmp_dir'):
                    temp_dir = Vault.get_vault_tmp_dir()
                else:
                    temp_dir = '/opt/phantom/vault/tmp'
                temp_dir = temp_dir + ('/{}').format(hashlib.md5(file_name).hexdigest())
                os.makedirs(temp_dir)
                file_path = os.path.join(temp_dir, 'tmpfile')
                with open(file_path, 'wb') as (f):
                    f.write(response)
                vault_ret = Vault.add_attachment(file_path, self.get_container_id(), file_name=file_name)
            if vault_ret.get('succeeded'):
                action_result.set_status(phantom.APP_SUCCESS, 'Downloaded Screenshot')
                summary = {phantom.APP_JSON_VAULT_ID: vault_ret[phantom.APP_JSON_HASH],
                        phantom.APP_JSON_NAME: file_name,
                        'vault_file_path': Vault.get_file_path(vault_ret[phantom.APP_JSON_HASH]),
                        phantom.APP_JSON_SIZE: vault_ret.get(phantom.APP_JSON_SIZE)}
                action_result.update_summary(summary)
            return action_result.get_status()

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'get_pdf':
            ret_val = self._handle_get_pdf(param)

        elif action_id == 'get_content':
            ret_val = self._handle_get_content(param)

        elif action_id == 'get_screenshot':
            ret_val = self._handle_get_screenshot(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._rest_url = config.get('URL')
        self._rest_token = config.get('token')
        self._base_url = config.get('base_url')

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
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
            login_url = BrowserlessIoConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
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
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = BrowserlessIoConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
