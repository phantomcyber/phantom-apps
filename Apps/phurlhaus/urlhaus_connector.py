# File: urlhaus_connector.py
# Copyright (c) 2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.#!/usr/bin/python
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

import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class UrlhausConnector(BaseConnector):

    def __init__(self):

        super(UrlhausConnector, self).__init__()

        self._state = None
        self._base_url = None

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        if not r.text:
            return self._process_empty_response(r, action_result)

        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                verify=config.get('verify_server_cert', False),
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
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to endpoint")
        ret_val, response = self._make_rest_call(
            '/urls/recent/limit/1', action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_url(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        url = param['url']
        data = {}
        data['url'] = url

        ret_val, response = self._make_rest_call(
            '/url', action_result, params=None, headers=None, method="post", data=data)

        if phantom.is_fail(ret_val):
            self.save_progress("Failed to contact URLhaus.")
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        if response['query_status'] == "no_results":
            summary['message'] = "No results found for: {0}".format(url)
        elif response['query_status'] == "ok":
            summary['date_added'] = response['date_added']
            payload_count = len(response['payloads'])
            summary['payload_count'] = payload_count
            summary['message'] = "URL {0} observed dropping {1} payloads".format(
                url, payload_count)
        summary['query_status'] = response['query_status']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_ip(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param['ip']
        data = {}
        data['host'] = ip

        ret_val, response = self._make_rest_call(
            '/host', action_result, params=None, headers=None, method="post", data=data)

        if phantom.is_fail(ret_val):
            self.save_progress("Failed to contact URLhaus.")
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        if response['query_status'] == "no_results":
            summary['message'] = "No results found for: {0}".format(ip)
        elif response['query_status'] == "ok":
            summary['firstseen'] = response['firstseen']
            url_count = len(response['urls'])
            summary['url_count'] = url_count
            summary['message'] = "IP {0} observed serving {1} URLs".format(ip, url_count)
        summary['query_status'] = response['query_status']
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_domain(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param['domain']
        data = {}
        data['host'] = domain

        ret_val, response = self._make_rest_call(
            '/host', action_result, params=None, headers=None, method="post", data=data)

        if phantom.is_fail(ret_val):
            self.save_progress("Failed to contact URLhaus.")
            return action_result.get_status()

        action_result.add_data(response)
        summary = action_result.update_summary({})
        if response['query_status'] == "no_results":
            summary['message'] = "No results found for: {0}".format(domain)
        elif response['query_status'] == "ok":
            summary['firstseen'] = response['firstseen']
            url_count = len(response['urls'])
            summary['url_count'] = url_count
            summary['message'] = "Domain {0}  observed serving {1} URLs".format(domain, url_count)
        summary['query_status'] = response['query_status']
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_hash(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        file_hash = param['file_hash']
        data = {}
        if len(file_hash) == 64:
            data['sha256_hash'] = file_hash
        elif len(file_hash) == 32:
            data['md5_hash'] = file_hash
        else:
            return action_result.set_status(
                phantom.APP_ERROR, "File Hash length not supported. Please verify hash is sha256 (64 char) or md5 (32)")

        ret_val, response = self._make_rest_call(
            '/payload', action_result, params=None, headers=None, method="post", data=data)

        if phantom.is_fail(ret_val):
            self.save_progress("Failed to contact URLhaus.")
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        if response['query_status'] == "no_results":
            summary['message'] = "No results found for: {0}".format(file_hash)
        elif response['query_status'] == "ok":
            summary['firstseen'] = response['firstseen']
            url_count = len(response['urls'])
            summary['url_count'] = url_count
            signature = response['signature']
            summary['message'] = "File Hash {0} observed being served by {1} URLs. Possible signature {2}".format(
                file_hash, url_count, signature)
        summary['query_status'] = response['query_status']
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'lookup_url':
            ret_val = self._handle_lookup_url(param)

        elif action_id == 'lookup_ip':
            ret_val = self._handle_lookup_ip(param)

        elif action_id == 'lookup_domain':
            ret_val = self._handle_lookup_domain(param)

        elif action_id == 'lookup_hash':
            ret_val = self._handle_lookup_hash(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

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
            login_url = UrlhausConnector._get_phantom_base_url() + '/login'

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

        connector = UrlhausConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
