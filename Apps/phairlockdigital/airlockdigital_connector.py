# File: airlockdigital_connector.py
# Copyright (c) 2019-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# This connector imports
from airlockdigital_consts import *
import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class AirlockDigitalConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(AirlockDigitalConnector, self).__init__()

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
            # If I can't parse the json
            self.save_progress("Failed to parse json naturally")
            try:
                resp_json = json.loads(str(r.text).replace("\\", "\\\\"))
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
        # Custom command
        self.save_progress("Making process response")
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

        config = self.get_config()

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
                            # auth=(username, password),  # basic authentication
                            verify=config.get('verify_server_cert', False),
                            **kwargs)

        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in its own variable.
        api_key = config.get('apiKey')

        # Parameter Dictionary to pass to the request
        header_var = {
            "X-APIKey": api_key
        }

        url = AIRLOCK_LICENSE_GET_ENDPOINT
        self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, response = self._make_rest_call(url, action_result, params=None, headers=header_var, method="post")

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Test Connectivity Failed. Error Message: {}".format(response['error']))
            # return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unblock_hash(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Optional values use get parameter
        blocklistid = param.get('blocklistid', '')

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Empty arrays
        url_req = []

        self.save_progress("File hash var: {}".format(param['hash']))
        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in its own variable.
        api_key = config.get('apiKey')

        # Parameter Dictionary to pass to the request
        header_var = {
            "X-APIKey": api_key
        }

        if (blocklistid == "" or None):
            self.save_progress("No blocklistid was specified, removing hash(es) from all blocklist packages")
            url = AIRLOCK_HASH_BLOCKLIST_REMOVE_ALL_ENDPOINT
            request_json = {
                "hashes": [param['hash']]
            }
        else:
            self.save_progress("Removing hash(es) from specified blocklist packages")
            url = AIRLOCK_HASH_BLOCKLIST_REMOVE_ENDPOINT
            request_json = {
                "hashes": [param['hash']],
                "blocklistid": blocklistid
            }

        # Parameter Dictionary to pass to the request
        header_var = {
           "X-APIKey": api_key
        }
        url_req.append({'url': url, 'header_var': header_var, 'request_type': 'blocklist'})

        # Make the request
        ret_val, response = self._make_rest_call(url, action_result, json=request_json, headers=header_var, method="post")

        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, "Failed to unblock hash, perhaps the specified blocklistid does not exist")

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['hash'] = request_json['hashes']
        # Return the first response outcome
        summary['result'] = response['error']

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_disallow_hash(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Optional values use get parameter
        applicationid = param.get('applicationid', '')

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Empty arrays
        url_req = []

        self.save_progress("File hash var: {}".format(param['hash']))
        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in its own variable.
        api_key = config.get('apiKey')

        # Parameter Dictionary to pass to the request
        header_var = {
            "X-APIKey": api_key
        }

        if (applicationid == "" or None):
            self.save_progress("No applicationid was specified, removing hash(es) from all application capture packages")
            url = AIRLOCK_HASH_APPLICATION_REMOVE_ALL_ENDPOINT
            request_json = {
                "hashes": [param['hash']]
            }
        else:
            self.save_progress("Removing hash(es) from specified application capture packages")
            url = AIRLOCK_HASH_APPLICATION_REMOVE_ENDPOINT
            request_json = {
                "hashes": [param['hash']],
                "applicationid": applicationid
            }

        # Parameter Dictionary to pass to the request
        header_var = {
           "X-APIKey": api_key
        }
        url_req.append({'url': url, 'header_var': header_var, 'request_type': 'application'})

        # Make the request
        ret_val, response = self._make_rest_call(url, action_result, json=request_json, headers=header_var, method="post")

        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, "Failed to unblock hash, perhaps the specified applicationid does not exist")

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['hash'] = request_json['hashes']
        # Return the first response outcome
        summary['result'] = response['error']

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_block_hash(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Empty arrays
        url_req = []

        self.save_progress("File hash var: {}".format(param['hash']))
        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in its own variable.
        api_key = config.get('apiKey')

        # Parameter Dictionary to pass to the request
        header_var = {
            "X-APIKey": api_key
        }

        url = AIRLOCK_HASH_BLOCKLIST_ADD_ENDPOINT
        # Required values can be accessed directly
        request_json = {
            "hashes": [param['hash']],
            "blocklistid": param['blocklistid']
        }
        # Parameter Dictionary to pass to the request
        header_var = {
           "X-APIKey": api_key
        }
        url_req.append({'url': url, 'header_var': header_var, 'request_type': 'blocklist'})

        # Make the request for each
        self.save_progress("Sending hash value to AIRLOCK_HASH_BLOCKLIST_ADD_ENDPOINT")
        ret_val, response = self._make_rest_call(url, action_result, json=request_json, headers=header_var, method="post")

        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, "Failed to block hash")

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['hash'] = request_json['hashes']
        # Return the first response outcome
        summary['result'] = response['error']

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_allow_hash(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Empty arrays
        url_req = []

        self.save_progress("File hash var: {}".format(param['hash']))
        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in its own variable.
        api_key = config.get('apiKey')

        # Parameter Dictionary to pass to the request
        header_var = {
            "X-APIKey": api_key
        }

        # We first need to populate the hash value into the airlock file repository, so it can be added into an appcap
        url = AIRLOCK_HASH_ADD_ENDPOINT

        # Required values can be accessed directly
        request_json = {
           "hashes": [{"path": param['path'], "sha256": param['hash']}]
        }
        # Parameter Dictionary to pass to the request
        header_var = {
           "X-APIKey": api_key
        }

        url_req.append({'url': url, 'header_var': header_var, 'request_type': 'application'})

        # Make the request to populate the application capture
        self.save_progress("Populating the Airlock repository with the specified hash value and path")
        ret_val, response = self._make_rest_call(url, action_result, json=request_json, headers=header_var, method="post")

        url2 = AIRLOCK_HASH_APPLICATION_ADD_ENDPOINT
        # Required values can be accessed directly
        request_json = {
            "hashes": [param['hash']],
            "applicationid": param['applicationid']
        }
        # Parameter Dictionary to pass to the request
        header_var = {
           "X-APIKey": api_key
        }
        url_req.append({'url': url2, 'header_var': header_var, 'request_type': 'application'})

        # Now put the added hash value from the repo into the application capture
        self.save_progress("Linking the new repository entry with the specified Application Capture")
        ret_val, response = self._make_rest_call(url2, action_result, json=request_json, headers=header_var, method="post")

        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, "Failed to add hash to application capture")

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['hash'] = request_json['hashes']
        # Return the first response outcome
        summary['result'] = response['error']

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_identifiers(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        policy_type = param['policy_type']

        # Add config to init variable to get root API Key
        config = self.get_config()

        # Response array
        resp_arr = []

        # Place api key in its own variable.
        api_key = config.get('apiKey')

        # Parameter Dictionary to pass to the request
        header_var = {
            "X-APIKey": api_key
        }

        # If policy type is blocklist
        if policy_type == 'blocklist':
            url = AIRLOCK_BLOCKLIST_ENDPOINT
            req_method = "post"

        # If policy type is baseline
        elif policy_type == 'baseline':
            url = AIRLOCK_BASELINE_ENDPOINT
            req_method = "post"

        # If policy type is application
        elif (policy_type == 'application'):
            url = AIRLOCK_APPLICATION_ENDPOINT
            req_method = "post"

        # If policy type is group
        elif (policy_type == 'group'):
            url = AIRLOCK_GROUP_ENDPOINT
            req_method = "post"

        else:
            return action_result.set_status(phantom.APP_ERROR, "Invalid policy type, must be either application, baseline, group or blocklist")

        # Make the request
        self.save_progress("Making request to URL: {} with request type of {}.".format(url, policy_type))
        ret_val, response = self._make_rest_call(url, action_result, headers=header_var, method=req_method)

        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, "Request Failed.  Error message: {}".format(response['error']))

        # Modify Baseline Requests to fit in the columns
        if policy_type == 'baseline':
            for i in response['response']['baselines']:
                self.save_progress("Request Format {}".format(i))
                resp_arr.append({"name": i['name'], "id": i['baselineid'], "type": "baseline"})
        # Modify blocklist Request to fit in columns
        if policy_type == 'blocklist':
            self.save_progress("blocklist request {}.".format(response))
            for i in response['response']['blocklists']:
                self.save_progress("Request Format {}".format(i))
                resp_arr.append({"name": i['name'], "id": i['blocklistid'], "type": "blocklist"})
        # Modify application Request to fit in columns
        if policy_type == 'application':
            for i in response['response']['applications']:
                self.save_progress("Request Format {}".format(i))
                resp_arr.append({"name": i['name'], "id": i['applicationid'], "type": "application"})
        # Modify group Request to fit in columns
        if policy_type == 'group':
            for i in response['response']['groups']:
                self.save_progress("Request Format {}".format(i))
                resp_arr.append({"name": i['name'], "id": i['groupid'], "parent": i['parent'], "type": "group"})

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(resp_arr)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['policy_type'] = policy_type
        # Return the first response outcome
        summary['result'] = response['error']

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_list_policy(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        group_id = param['group_id']

        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in its own variable.
        api_key = config.get('apiKey')

        # Parameter Dictionary to pass to the request
        header_var = {
            "X-APIKey": api_key
        }

        # URL Group Request
        url = AIRLOCK_GROUP_POLICIES_ENDPOINT

        # Put the group ID to request in the JSON blody
        json_body = {"groupid": group_id}

        # make rest call that iterates over each url
        # Make the request for each
        self.save_progress("Making request to URL: {}".format(url))
        ret_val, response = self._make_rest_call(url, action_result, json=json_body, headers=header_var, method="post")

        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, "Failed to request group list ")

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        # Return the first response outcome
        summary['result'] = response['error']

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_move_endpoints(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in its own variable.
        api_key = config.get('apiKey')

        # Parameter Dictionary to pass to the request
        header_var = {
            "X-APIKey": api_key
        }

        # URL Group Request
        url = AIRLOCK_AGENT_MOVE_ENDPOINT

        # Group ID Parameter
        group_id = param['group_id']

        # Agent ID Parameter
        agent_id = param['agent_id']

        json_body = {"agentid": agent_id, "groupid": group_id}
        # Make the request for each
        self.save_progress("Making request to URL: {}".format(url))
        ret_val, response = self._make_rest_call(url, action_result, headers=header_var, json=json_body, method="post")

        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, "Failed to move endpoint")

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        # Return the first response outcome
        summary['result'] = response['error']

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_endpoints(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Optional values should use the .get() function
        ip = param.get('ip', '')
        hostname = param.get('hostname', '')
        domain = param.get('domain', '')
        agentid = param.get('agentid', '')
        username = param.get('username', '')
        groupid = param.get('groupid', '')
        os = param.get('os', '')
        status = param.get('status', '')
        if domain == "all":
            domain = ""

        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in its own variable.
        api_key = config.get('apiKey')

        # Parameter Dictionary to pass to the request
        header_var = {
            "X-APIKey": api_key,
        }
        # If optional parameters are set, then add them to the header_var dictionary
        # Create an iterator to identify the correct header field
        x = 0
        param_var = {}
        for a in [ip, hostname, domain, agentid, username, groupid, os, status]:
            if len(a) > 0:
                if x == 0:
                    param_var["ip"] = a
                elif x == 1:
                    param_var["hostname"] = a
                elif x == 2:
                    param_var["domain"] = a
                elif x == 3:
                    param_var["agentid"] = a
                elif x == 4:
                    param_var["username"] = a
                elif x == 5:
                    param_var["groupid"] = a
                elif x == 6:
                    param_var["os"] = a
                elif x == 7:
                    param_var["status"] = a
            x += 1

        # make rest call
        # If more than one parameter is set
        if len(param_var.keys()) >= 1:
            if param_var["hostname"] != "all":
                self.save_progress("Requested parameters: {}".format(param_var))
                ret_val, response = self._make_rest_call(AIRLOCK_AGENT_FIND_ENDPOINT, action_result, json=param_var, headers=header_var, method="post")
            else:
                param_var.pop('hostname')
                self.save_progress("Requested parameters: {}".format(param_var))
                self.save_progress("All has been specified in hostname, so returning all hosts")
                ret_val, response = self._make_rest_call(AIRLOCK_AGENT_FIND_ENDPOINT, action_result, headers=header_var, method="post")

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            # return action_result.get_status()
            return action_result.set_status(phantom.APP_ERROR, "Failed to list endpoints for Airlock Digital.  Error Message {}".format(response['error']))

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response['response']['agents'])
        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['result'] = response['error']

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_otp_revoke(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        otpid = param['otpid']

        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in its own variable.
        api_key = config.get('apiKey')

        # Parameter Dictionary to pass to the request
        header_var = {
            "X-APIKey": api_key,
        }
        param_var = {
            "otpid": otpid
        }

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make rest call
        ret_val, response = self._make_rest_call(AIRLOCK_OTP_REVOKE_ENDPOINT, action_result, params=param_var, headers=header_var, method="post")

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            # return action_result.get_status()
            return action_result.set_status(phantom.APP_ERROR, "Failed to revoke OTP for Airlock Digital.  Error Message {}".format(response['error']))

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['status'] = action_result['error']

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_otp_retrieve(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        agentid = param['agentid']
        purpose = param['purpose']

        # Optional values should use the .get() function
        duration = param['duration']

        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in its own variable.
        api_key = config.get('apiKey')

        # Parameter Dictionary to pass to the request
        header_var = {
            "X-APIKey": api_key,
        }

        param_var = {
            "agentid": agentid,
            "purpose": purpose,
            "duration": duration
        }

        # make rest call
        ret_val, response = self._make_rest_call(AIRLOCK_OTP_RETRIEVE_ENDPOINT, action_result, params=param_var, headers=header_var, method="post")

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            # return action_result.get_status()
            return action_result.set_status(phantom.APP_ERROR, "Failed to retrieve OTP for Airlock Digital.  Error Message {}".format(response['error']))

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['result'] = response['error']

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_lookup_hash(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        hash_var = param['hash']
        hash_var = [hash_var]
        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in its own variable.
        api_key = config.get('apiKey')

        # Parameter Dictionary to pass to the request
        header_var = {
            "X-APIKey": api_key,
            "Content-Type": "application/json"
        }

        data_var = {
            "hashes": hash_var
        }
        # Convert data variable to a json output to send to Airlock
        data_var = json.dumps(data_var)

        # make rest call
        ret_val, response = self._make_rest_call(AIRLOCK_HASH_QUERY_ENDPOINT, action_result, headers=header_var, method="post", data=data_var)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            # return action_result.get_status()
            return action_result.set_status(phantom.APP_ERROR, "Failed to lookup hash for Airlock Digital.  Error Message {}".format(response['error']))

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        # summary = action_result.update_summary({})
        # summary['result'] = response['error']

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'unblock_hash':
            ret_val = self._handle_unblock_hash(param)

        elif action_id == 'disallow_hash':
            ret_val = self._handle_disallow_hash(param)

        elif action_id == 'allow_hash':
            ret_val = self._handle_allow_hash(param)

        elif action_id == 'block_hash':
            ret_val = self._handle_block_hash(param)

        elif action_id == 'list_endpoints':
            ret_val = self._handle_list_endpoints(param)

        elif action_id == 'move_endpoints':
            ret_val = self._handle_move_endpoints(param)

        elif action_id == 'list_identifiers':
            ret_val = self._handle_list_identifiers(param)

        elif action_id == 'list_policy':
            ret_val = self._handle_list_policy(param)

        elif action_id == 'otp_revoke':
            ret_val = self._handle_otp_revoke(param)

        elif action_id == 'otp_retrieve':
            ret_val = self._handle_otp_retrieve(param)

        elif action_id == 'lookup_hash':
            ret_val = self._handle_lookup_hash(param)
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

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            login_url = AirlockDigitalConnector._get_phantom_base_url() + '/login'

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

        connector = AirlockDigitalConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
