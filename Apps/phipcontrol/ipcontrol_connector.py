# File: ipcontrol_connector.py
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from ipcontrol_consts import *
import requests
import json
import re
from bs4 import BeautifulSoup
from ipcontrol_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class IpControlConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(IpControlConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

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

    def _get_auth_token(self, action_result):
        config = self.get_config()

        # try:
        #     auth_func = getattr(requests, "post")
        # except AttributeError:
        #     return "False"

        auth_endpoint = IPCONTROL_ENDPOINT_LOGIN
        # api = "/inc-rest/api/v1"

        auth_username = config.get('username', '')
        auth_password = config.get('password', '')

        # auth_url = self._base_url + api + auth_endpoint

        data = {'username': auth_username, 'password': auth_password}

        ret_val, response = self._make_rest_call(auth_endpoint, action_result, method="post", data=data)

        if phantom.is_fail(ret_val):
            self.debug_print(action_result.get_message())
            self.set_status(phantom.APP_ERROR, action_result.get_message())
            return None

        auth_token = response["access_token"]
        return auth_token

    def _make_rest_call(self, endpoint, action_result, method, **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        api = IPCONTROL_ENDPOINT

        # Create a URL to connect to
        url = self._base_url + api + endpoint

        try:
            r = request_func(
                            url,
                            # auth=(auth_username, auth_password),  # basic authentication
                            verify=config.get('verify_server_cert', False), **kwargs)

        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Testing connectivity")

        auth_token = self._get_auth_token(action_result)
        if not auth_token:
            self.save_progress(IPCONTROL_ERR_TEST_CONNECTIVITY)
            return action_result.get_message()

        # Return success
        self.save_progress(IPCONTROL_SUCC_TEST_CONNECTIVITY)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_block_type(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        # required_parameter = param['required_parameter']

        # Optional values should use the .get() function
        ip_address = param.get('ip_address', '')
        hostname = param.get('hostname', '')

        # api = "/inc-rest/api/v1"
        auth_token = self._get_auth_token(action_result)
        if not auth_token:
            return action_result.get_message()
        # Create a URL to connect to
        # endpoint = '/Exports/initExportChildBlock'
        # url = self._base_url + api + endpoint

        if ip_address != "":
            query = '{"query": "ipAddress=%s","pageSize": 0,"includeFreeBlocks": True,"firstResultPos": 0}' % (ip_address)
        elif hostname != "":
            query = '{"query": "hostname=%s", "pageSize": 0, "includeFreeBlocks": True, "firstResultPos": 0}' % (hostname)

        data = query
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + auth_token,
            "Content-Type": "application/json"
        }

        # make rest call
        ret_val, response = self._make_rest_call(IPCONTROL_ENDPOINT_GET_BLOCK_TYPE, action_result, method="post", headers=headers, data=data)

        if phantom.is_fail(ret_val):
            self.debug_print(action_result.get_message())
            self.set_status(phantom.APP_ERROR, action_result.get_message())
            return phantom.APP_ERROR

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        # TODO change datapath
        if response:
            action_result.add_data(response)
        else:
            action_result.add_data({'result': IPCONTROL_ERR_NO_DATA_FOUND})
        # action_result.add_data(response[0]['childBlock'])

        # Add a dictionary that is made up of the most important values from data into the summary
        # summary = action_result.update_summary({})
        # summary['num_data'] = len(action_result['data'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary

    def _handle_get_ip_address(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        hostname = param['hostname']
        auth_token = self._get_auth_token(action_result)
        if not auth_token:
            return action_result.get_message()
        headers = {'Authorization': "Bearer " + auth_token}

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make rest call
        ret_val, response = self._make_rest_call(IPCONTROL_ENDPOINT_GET_IP_ADDRESS + hostname, action_result, method="get", headers=headers, params=None)

        if phantom.is_fail(ret_val):
            self.debug_print(action_result.get_message())
            self.set_status(phantom.APP_ERROR, action_result.get_message())
            return phantom.APP_ERROR

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        if response:
            action_result.add_data(response)
        else:
            action_result.add_data({'result': IPCONTROL_ERR_NO_DATA_FOUND})

        # Add a dictionary that is made up of the most important values from data into the summary
        # summary = action_result.update_summary({})
        # summary['num_data'] = len(action_result['data'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary

    def _handle_get_hostname(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        ip_address = param['ip_address']
        auth_token = self._get_auth_token(action_result)
        if not auth_token:
            return action_result.get_message()
        headers = {'Authorization': "Bearer " + auth_token}

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make rest call
        ret_val, response = self._make_rest_call(IPCONTROL_ENDPOINT_GET_HOSTNAME + ip_address, action_result, method="get", headers=headers, params=None)

        if phantom.is_fail(ret_val):
            self.debug_print(action_result.get_message())
            self.set_status(phantom.APP_ERROR, action_result.get_message())
            return phantom.APP_ERROR

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        if response:
            action_result.add_data(response)
        else:
            action_result.add_data({'result': IPCONTROL_ERR_NO_DATA_FOUND})

        # Add a dictionary that is made up of the most important values from data into the summary
        # summary = action_result.update_summary({})
        # summary['num_data'] = len(action_result['data'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_child_block(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        name = param.get('name', '')
        block = param.get('block', '')
        blockType = param.get('block_type', '')
        container = param.get('container', '')
        createDate = param.get('create_date', '')
        lastUpdate = param.get('last_update', '')
        parentContainer = param.get('parent_container', '')
        status = param.get('status', '')
        ipVersion = param.get('ip_version', '')
        udf = param.get('udf', '')
        # query = {'name': name, 'block': block, 'blockType': blockType, 'container': container}

        auth_token = self._get_auth_token(action_result)
        if not auth_token:
            return action_result.get_message()

        query = '{"query": "name=\'%s\' and block=\'%s\' and blockType=\'%s\' and container=\'%s\' and createDate=\'%s\'' \
                ' and lastUpdate=\'%s\' and parentContainer=\'%s\' and status=\'%s\' and ipVersion=\'%s\' and udf=\'%s\'", ' \
                '"pageSize": 0, "includeFreeBlocks": True, "firstResultPos": 0}'\
                % (str(name), block, blockType, container, createDate, lastUpdate, parentContainer, status, ipVersion, udf)

        if name == '':
            query = query.replace('name=\'\' and', '')
            query = re.sub(' +', ' ', query)
        if block == '':
            query = query.replace('block=\'\' and', '')
            query = re.sub(' +', ' ', query)
        if blockType == '':
            query = query.replace('blockType=\'\' and', '')
            query = re.sub(' +', ' ', query)
        if container == '':
            query = query.replace('container=\'\' and', '')
            query = re.sub(' +', ' ', query)
        if createDate == '':
            query = query.replace('createDate=\'\' and', '')
            query = re.sub(' +', ' ', query)
        if lastUpdate == '':
            query = query.replace('lastUpdate=\'\' and', '')
            query = re.sub(' +', ' ', query)
        if parentContainer == '':
            query = query.replace('parentContainer=\'\' and', '')
            query = re.sub(' +', ' ', query)
        if status == '':
            query = query.replace('status=\'\' and', '')
            query = re.sub(' +', ' ', query)
        if ipVersion == '':
            query = query.replace('ipVersion=\'\' and', '')
            query = re.sub(' +', ' ', query)
        if udf == '':
            query = query.replace('and udf=\'\'', '')
            query = re.sub(' +', ' ', query)

        data = query

        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + auth_token,
            "Content-Type": "application/json"
        }

        # make rest call
        ret_val, response = self._make_rest_call(IPCONTROL_ENDPOINT_GET_CHILD_BLOCK, action_result, method="post",
                                                 headers=headers, data=data)

        if phantom.is_fail(ret_val):
            self.debug_print(action_result.get_message())
            self.set_status(phantom.APP_ERROR, action_result.get_message())
            return phantom.APP_ERROR

        if response:
            action_result.add_data(response)
        else:
            action_result.add_data({'result': IPCONTROL_ERR_NO_DATA_FOUND})

        # Add a dictionary that is made up of the most important values from data into the summary
        # summary = action_result.update_summary({})
        # summary['num_data'] = len(action_result['data'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'get_block_type':
            ret_val = self._handle_get_block_type(param)

        elif action_id == 'get_ip_address':
            ret_val = self._handle_get_ip_address(param)

        elif action_id == 'get_hostname':
            ret_val = self._handle_get_hostname(param)

        elif action_id == 'get_child_block':
            ret_val = self._handle_get_child_block(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get('base_url')

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

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = IpControlConnector._get_phantom_base_url() + '/login'

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

        connector = IpControlConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
