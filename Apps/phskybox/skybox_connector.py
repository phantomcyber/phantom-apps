# File: skybox_connector.py
#
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from skybox_consts import *
import requests
import json
import base64
import ssl

from datetime import datetime
from bs4 import BeautifulSoup, UnicodeDammit
from urllib2 import HTTPSHandler
from suds.client import Client
from suds.sudsobject import asdict
from suds.transport.https import HttpAuthenticated


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class NoVerifyTransport(HttpAuthenticated):
    def u2handlers(self):
        handlers = HttpAuthenticated.u2handlers(self)
        context = ssl._create_unverified_context()
        handlers.append(HTTPSHandler(context=context))
        return handlers


class SkyboxConnector(BaseConnector):

    def __init__(self):

        super(SkyboxConnector, self).__init__()

        self._state = None

        self._base_url = None

    def _create_client(self, action_result, service):
        try:
            try:
                _create_unverified_https_context = ssl._create_unverified_context
            except AttributeError:
                pass
            else:
                ssl._create_default_https_context = _create_unverified_https_context

            wsdl_url = SKYBOX_WSDL.format(base_url=self._base_url, service=service)
            base64string = base64.encodestring('%s:%s' % (self._username, self._password)).replace('\n', '')
            authenticationHeader = {
                "Authorization": "Basic %s" % base64string
            }
            self._client = Client(url=wsdl_url, headers=authenticationHeader)

        except Exception as e:
            if e.message:
                try:
                    error_msg = UnicodeDammit(e.message).unicode_markup.encode('utf-8')
                except:
                    error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."
            else:
                error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."
            # self.save_progress("Last Sent: {}\r\n\r\nLast Received: {}".format(self._client.last_sent(), self._client.last_received()))
            return action_result.set_status(phantom.APP_ERROR, 'Could not connect to the Skybox Security API endpoint {0}'.format(error_msg))

        return phantom.APP_SUCCESS

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
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

        message = message.replace(u'{', '{{').replace(u'}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace(u'{', '{{').replace(u'}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                            url,
                            verify=False,
                            **kwargs)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _suds_to_dict(self, sud_obj):
        if hasattr(sud_obj, '__keylist__'):

            sud_dict = asdict(sud_obj)
            new_dict = {}

            for key in sud_dict:
                new_dict[key] = self._suds_to_dict(sud_dict[key])

            return new_dict

        elif isinstance(sud_obj, list):
            new_list = []
            for elm in sud_obj:
                new_list.append(self._suds_to_dict(elm))
            return new_list

        elif isinstance(sud_obj, datetime):
            try:
                return sud_obj.strftime("%Y-%m-%dT%H:%M:%S%z")
            except ValueError:
                return None

        # Checking for NaN
        elif sud_obj != sud_obj:
            return None

        return sud_obj

    def _get_vulnerabilities(self, action_result, assets):
        ret_val = self._create_client(action_result, SKYBOX_SERVICE_VULNERABILITIES)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for asset in assets:
            try:
                vuln_filter = {
                    'scope': {
                        'ids': [asset.get('id', -1)]
                    }
                }
                subRange = {
                    'start': 0,
                    'size': 10000
                }

                response = self._client.service.getVulnerabilities(vuln_filter, subRange)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, 'SOAP call to Skybox failed', e)

            if not response:
                return action_result.set_status(phantom.APP_ERROR, "No access returned or response was empty")

            vulns = self._suds_to_dict(response)

            if len(vulns):
                asset.update({'vulnerabilities': vulns})
        return RetVal(phantom.APP_SUCCESS, assets)

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Testing network service for connectivity...")

        ret_val = self._create_client(action_result, SKYBOX_SERVICE_NETWORK)
        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # running testService method
        try:
            self._client.service.testService(1234)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Test Connectivity Failed.", e)

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_ip(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        ip = param['ip']
        ret_val = self._create_client(action_result, SKYBOX_SERVICE_NETWORK)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            subRange = {
                'start': 0,
                'size': 10000
            }

            response = self._client.service.findAssetsByIps(ip, subRange)
        except Exception as e:
            # self.save_progress("Last Sent: {}\r\n\r\nLast Received: {}".format(self._client.last_sent(), self._client.last_received()))
            return action_result.set_status(phantom.APP_ERROR, 'SOAP call to Skybox failed', e)

        if not response:
            return action_result.set_status(phantom.APP_ERROR, "No access returned or response was empty")

        assets = self._suds_to_dict(response).get('assets', [])

        ret_val, assets = self._get_vulnerabilities(action_result, assets)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if len(assets):
            action_result.update_data(assets)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'lookup_ip':
            ret_val = self._handle_lookup_ip(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._base_url = config.get(SKYBOX_CONFIG_BASE_URL).rstrip('/')
        self._base_url = UnicodeDammit(self._base_url).unicode_markup.encode('utf-8')
        self._username = UnicodeDammit(config[SKYBOX_CONFIG_USERNAME]).unicode_markup.encode('utf-8')
        self._password = config[SKYBOX_CONFIG_PASSWORD]
        self._auth = base64.b64encode('{0}:{1}'.format(self._username, self._password))
        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


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
            login_url = SkyboxConnector._get_phantom_base_url() + '/login'

            print ("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print ("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SkyboxConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
