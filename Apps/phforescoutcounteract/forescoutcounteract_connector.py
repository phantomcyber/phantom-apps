# File: forescoutcounteract_connector.py
# Copyright (c) 2018-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from forescoutcounteract_consts import *
import requests
import json
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from urllib.parse import unquote


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class ForescoutCounteractConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(ForescoutCounteractConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error messages from the exception.
        :param e: Exception object
        :return: error message
        """

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = FS_ERR_CODE_MSG
                    error_msg = e.args[0]
            else:
                error_code = FS_ERR_CODE_MSG
                error_msg = FS_ERR_MSG_UNAVAILABLE
        except:
            error_code = FS_ERR_CODE_MSG
            error_msg = FS_ERR_MSG_UNAVAILABLE

        try:
            if error_code in FS_ERR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
        except:
            self.debug_print("Error occurred while parsing error message")
            error_text = FS_PARSE_ERR_MSG

        return error_text

    def _validate_integer(self, action_result, parameter, key):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, ERR_VALID_INT_MSG.format(key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, ERR_VALID_INT_MSG.format(key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, ERR_NON_NEG_INT_MSG.format(key)), None

            if parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, ERR_POSITIVE_INTEGER_MSG.format(key)), None

        return phantom.APP_SUCCESS, parameter

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Status Code: {}. Empty response and no information in the header".format(response.status_code)
            ), None
        )

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
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

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(err), None))

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, unquote(r.text.replace('{', '{{').replace('}', '}}')))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_xml_response(self, r, action_result):

        # Try an XML parse
        try:
            resp_xml = ET.fromstring(r.text)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse XML response. Error: {0}".format(err), None))

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_xml)

        # You should process the error returned in the json
        if resp_xml:
            message = "Error from server. Status Code: {0} Data from server: {1}".format(
                    resp_xml.find(".//CODE").text, resp_xml.find(".//MESSAGE").text)
        else:
            message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text)

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

        # Process a xml response
        if '<?xml' in r.text:
            return self._process_xml_response(r, action_result)

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

    def _verify_dex_allowed(self, action_result):

        config = self.get_config()

        if config.get('dex_username') and config.get('dex_password') and config.get('dex_account'):
            return (phantom.APP_SUCCESS, "")

        return (phantom.APP_ERROR, "DEX credentials incomplete. Action cannot be completed")

    def _verify_web_allowed(self, action_result):

        config = self.get_config()

        if config.get('web_username') and config.get('web_password'):
            return (phantom.APP_SUCCESS, "")

        return (phantom.APP_ERROR, "Web credentials incomplete. Action cannot be completed")

    def _get_web_jwt_token(self, action_result):

        config = self.get_config()
        self.save_progress("Creating JWT for Web API call")

        url = self._base_url + FS_WEB_LOGIN
        header = {'Content-Type': 'application/x-www-form-urlencoded'}
        body = {'username': config['web_username'], 'password': config['web_password']}

        try:
            response = requests.post(url, headers=header, data=body, verify=config.get('verify_server_cert', False))
            token = response.text
        except:
            return (phantom.APP_ERROR, "Could not retrieve JWT")

        return (phantom.APP_SUCCESS, token)

    def _make_rest_call(self, module, endpoint, action_result, method="get", auth=None, headers=None, **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        if module == 'dex':
            status, msg = self._verify_dex_allowed(action_result)

            if phantom.is_fail(status):
                return RetVal(action_result.set_status(phantom.APP_ERROR, msg), None)

            auth = ("{}@{}".format(config['dex_username'], config['dex_account']).encode('utf-8'), config['dex_password'])
            headers = {'Content-Type': 'application/xml'}

        if module == 'web':
            status, msg = self._verify_web_allowed(action_result)

            if phantom.is_fail(status):
                return RetVal(action_result.set_status(phantom.APP_ERROR, msg), None)

            ret_val, token = self._get_web_jwt_token(action_result)

            if phantom.is_fail(ret_val):
                return RetVal(action_result.set_status(phantom.APP_ERROR, token), None)

            headers = {
                'Authorization': token,
                'Accept': 'application/ha1+json'
            }

        # Create a URL to connect to
        url = "{}{}".format(self._base_url, endpoint)

        try:
            r = request_func(
                            url,
                            auth=auth,
                            headers=headers,
                            verify=config.get('verify_server_cert', False),
                            **kwargs)
        except requests.exceptions.InvalidSchema:
            error_message = "Error connecting to server. No connection adapters were found for %s" % (url)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except requests.exceptions.ConnectionError:
            error_message = "Error connecting to server. Connection Refused from the Server for invalid URL %s" % (url)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(err), resp_json))

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        config = self.get_config()

        dex_credentials = config.get('dex_account') and config.get('dex_username') and config.get('dex_password')
        web_credentials = config.get('web_username') and config.get('web_password')

        if not dex_credentials and not web_credentials:
            self.save_progress("Test Connectivity Failed")
            return action_result.set_status(phantom.APP_ERROR, "The credential of DEX or Web API must be provided")

        if dex_credentials:
            # Test connectivity for DEX
            self.save_progress("Connecting to endpoint {} to test DEX connectivity".format(FS_DEX_HOST_ENDPOINT))

            data = FS_DEX_TEST_CONNECTIVITY.format(host_key_value=config['device'])

            # make rest call
            ret_val, response = self._make_rest_call('dex', FS_DEX_HOST_ENDPOINT, action_result, data=data, method='post')

            if phantom.is_fail(ret_val):
                self.save_progress("Test Connectivity for DEX Failed")
                return action_result.get_status()

            # Return success
            self.save_progress("Test Connectivity for DEX Passed")
        else:
            self.save_progress("Credentials for DEX not supplied. Skipping test connectivity for DEX")

        if web_credentials:
            # Test connectivity for web
            self.save_progress("Connecting to endpoint {} to test Web API connectivity".format(FS_WEB_HOSTS))

            # make rest call
            ret_val, response = self._make_rest_call('web', FS_WEB_HOSTS, action_result)

            if phantom.is_fail(ret_val):
                self.save_progress("Test Connectivity for web Failed")
                return action_result.get_status()

            # Return success
            self.save_progress("Test Connectivity for web Passed")
        else:
            self.save_progress("Credentials for web not supplied. Skipping test connectivity for web")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_hosts(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # make rest call
        ret_val, response = self._make_rest_call('web', FS_WEB_HOSTS, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        for item in response['hosts']:
            action_result.add_data(item)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_hosts'] = len(response['hosts'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_policies(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # make rest call
        ret_val, response = self._make_rest_call('web', FS_WEB_POLICIES, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        for item in response['policies']:
            action_result.add_data(item)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_policies'] = len(response['policies'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_host_properties(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        host_id = param.get('host_id')
        host_ip = param.get('host_ip')
        host_mac = param.get('host_mac')

        ret_val, host_id = self._validate_integer(action_result, host_id, HOST_ID_INT_PARAM)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if host_id:
            url = '{}/{}'.format(FS_WEB_HOSTS, host_id)
        elif host_ip:
            url = '{}/ip/{}'.format(FS_WEB_HOSTS, host_ip)
        elif host_mac:
            url = '{}/mac/{}'.format(FS_WEB_HOSTS, host_mac)
        else:
            return action_result.set_status(phantom.APP_ERROR, 'One of the following need to be provided: host_id, host_ip, or host_mac')

        # make rest call
        ret_val, response = self._make_rest_call('web', url, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response['host'])

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['host_ip'] = response.get('host', {}).get('ip', 'missing')
        summary['host_mac'] = response.get('host', {}).get('mac', 'missing')
        summary['host_id'] = response.get('host', {}).get('id', 'missing')

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_active_sessions(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        params = '?'

        rule_id = param.get('rule_id')
        if rule_id:
            rule_id_list = []
            for item in rule_id.split(','):
                item = item.strip()
                if item:
                    rule_id_list.append(item)
                else:
                    return action_result.set_status(phantom.APP_ERROR, "Please provide a valid value in 'rule_id' action parameter")
            if rule_id_list:
                params += "matchRuleId=" + ",".join(rule_id_list)

        prop_val = param.get('prop_val')
        if prop_val:
            if rule_id:
                params += "&"
            prop_val_list = []
            for item in prop_val.split(','):
                item = item.strip()
                if item:
                    prop_val_list.append(item)
                else:
                    return action_result.set_status(phantom.APP_ERROR, "Please provide a valid value in 'prop_val' action parameter")
            if prop_val_list:
                params += "&".join(prop_val_list)

        url = FS_WEB_HOSTS
        if rule_id or prop_val:
            url += params

        # make rest call
        ret_val, response = self._make_rest_call('web', url, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        for item in response['hosts']:
            action_result.add_data(item)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_active_sessions'] = len(response['hosts'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_property(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        host_key_name = param['host_key_name']
        host_key_value = param['host_key_value']
        property_name = param['property_name']

        data = FS_DEX_DELETE_SIMPLE_PROPERTY.format(host_key_name=host_key_name,
                                                host_key_value=host_key_value, property_name=property_name)

        # make rest call
        ret_val, response = self._make_rest_call('dex', FS_DEX_HOST_ENDPOINT, action_result, data=data, method='post')

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        action_result.add_data({'host_key_name': host_key_name,
                                'host_key_value': host_key_value,
                                'property_name': property_name,
                                'response_code': response.find(".//CODE").text,
                                'response_message': response.find(".//MESSAGE").text})

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['message'] = response.find(".//MESSAGE").text

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_property(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        host_key_name = param['host_key_name']
        host_key_value = param['host_key_value']
        property_name = param['property_name']
        property_value = param['property_value']
        create_host = str(param.get('create_host', True)).lower()

        data = FS_DEX_UPDATE_SIMPLE_PROPERTY.format(create_host=create_host,
                                         host_key_name=host_key_name, host_key_value=host_key_value,
                                         property_name=property_name, property_value=property_value)

        # make rest call
        ret_val, response = self._make_rest_call('dex', FS_DEX_HOST_ENDPOINT, action_result, data=data, method='post')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data({'host_key_name': host_key_name,
                                'host_key_value': host_key_value,
                                'property_name': property_name,
                                'property_value': property_value,
                                'response_code': response.find(".//CODE").text,
                                'response_message': response.find(".//MESSAGE").text})

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['message'] = response.find(".//MESSAGE").text

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_list_property(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        transaction_type = param['action'].replace(" ", "_")
        list_name = param['list_name']
        values = param.get('values')

        list_body = ""
        if transaction_type == "delete_all_list_values":
            list_body = '<LIST NAME="{}"></LIST>'.format(list_name)
        else:
            if not values:
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Please provide values in 'values' action parameter"), None)
            list_of_values = "".join(["<VALUE>" + item.strip() + "</VALUE>" for item in values.split(',')])
            list_body = '<LIST NAME="{}">{}</LIST>'.format(list_name, list_of_values)

        data = FS_DEX_UPDATE_LIST_PROPERTY.format(transaction_type=transaction_type, list_body=list_body)

        # make rest call
        ret_val, response = self._make_rest_call('dex', FS_DEX_LIST_ENDPOINT, action_result, data=data, method='post')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['message'] = response.find(".//MESSAGE").text

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'list_hosts':
            ret_val = self._handle_list_hosts(param)

        elif action_id == 'list_policies':
            ret_val = self._handle_list_policies(param)

        elif action_id == 'list_host_properties':
            ret_val = self._handle_list_host_properties(param)

        elif action_id == 'get_active_sessions':
            ret_val = self._handle_get_active_sessions(param)

        elif action_id == 'install_vfw':
            ret_val = self._handle_update_property(param)

        elif action_id == 'delete_property':
            ret_val = self._handle_delete_property(param)

        elif action_id == 'update_property':
            ret_val = self._handle_update_property(param)

        elif action_id == 'update_list_property':
            ret_val = self._handle_update_list_property(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._base_url = 'https://' + config.get('device')

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
    argparser.add_argument('-', '--username', help='username', required=False)
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
            login_url = "{}/login".format(BaseConnector._get_phantom_base_url())
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
            print("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ForescoutCounteractConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
