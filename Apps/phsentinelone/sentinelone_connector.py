# File: sentinelone_connector.py
# Copyright (c) 2018-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

import requests
import json
from bs4 import BeautifulSoup, UnicodeDammit
import sys


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class SentineloneConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(SentineloneConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._api_v = "/web/api/v2.1"
        self.HEADER = {"Content-Type": "application/json"}

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.
        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """
        try:
            if input_str and self._python_version < 3:
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except Exception:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def _get_error_message_from_exception(self, e):
        """ This function is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."
        error_code = "Error code unavailable"
        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = "Error code unavailable"
                    error_msg = e.args[0]
            else:
                error_code = "Error code unavailable"
                error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."
        except:
            error_code = "Error code unavailable"
            error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = "Error occurred while connecting to the SentinelOne server. Please check the asset configuration and|or the action parameters."
        except:
            error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

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

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')

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
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

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

        # Process an HTML resonse, Do this no matter what the api talks.
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

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method='get'):

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + self._api_v + str(endpoint)

        self.save_progress(url)
        try:
            r = request_func(
                            url,
                            json=data,
                            headers=headers,
                            verify=config.get('verify_server_cert', True),
                            params=params)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(error_message)), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to the SentinelOne server")

        # make rest call
        headers = self.HEADER
        headers["Authorization"] = "APIToken %s" % self.token
        ret_val, response = self._make_rest_call('/private/threats/summary', action_result, headers=headers)
        self.save_progress("response: {0}".format(response))

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            self.save_progress("Test Connectivity Failed. Error: {0}".format(action_result.get_message()))
            return action_result.get_status()

        # Return success
        self.save_progress("Login to SentinelOne server is successful")
        self.save_progress("Test Connectivity passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_site_ids(self, sites, headers, action_result):
        sites_tokens = [each.strip() for each in sites.split(",")]
        sites_tokens = list(filter(None, sites_tokens))
        site_ids = []
        try:
            url = self._base_url + self._api_v + "/sites"
            for site in sites_tokens:
                param = {"registrationToken": site}
                ret = requests.get(url, headers=headers, params=param)
                sites_data = ret.json().get('data', {}).get('sites', [])
                if sites_data:
                    site_data = sites_data[0]
                    site_id = site_data.get('id')
                    if site_id:
                        site_ids.append(site_id)
                    else:
                        self.debug_print("The site_token:{0} is invalid and is getting ignored".format(site))

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, "Error occurred while getting site ID : {0}".format(str(e)))
            return None

        # if site_ids is empty/none then it return None, provided side_tokens were invalid
        if not site_ids:
            action_result.set_status(phantom.APP_ERROR, "Please provide valid site token(s)")
            return None
        return site_ids

    def _handle_block_hash(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        hash = self._handle_py_ver_compat_for_input_str(param['hash'])
        description = self._handle_py_ver_compat_for_input_str(param['description'])
        os_family = self._handle_py_ver_compat_for_input_str(param['os_family'])
        sites = self._handle_py_ver_compat_for_input_str(param['sites_tokens'])

        summary = action_result.update_summary({})
        summary['hash'] = hash
        summary['description'] = UnicodeDammit(description).unicode_markup

        headers = self.HEADER
        headers["Authorization"] = "APIToken %s" % self.token
        headers["Content-Type"] = "application/json"

        # Fetch siteIds from siteToken
        site_ids = self._get_site_ids(sites, headers, action_result)

        if site_ids is None:
            return action_result.get_status()

        body = {
            "filter": {
                "siteIds": site_ids,
                "tenant": True
            },
            "data": {
                "description": description,
                "value": hash,
                "source": "sentinelone_connector",
                "osType": os_family,
                "type": "black_hash",
            }
        }

        try:
            ret_val, _ = self._make_rest_call('/restrictions', action_result, headers=headers, method='post', data=body)
            if (phantom.is_fail(ret_val)):
                return action_result.get_status()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while getting restrictions: {0}".format(e))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unblock_hash(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        hash = self._handle_py_ver_compat_for_input_str(param['hash'])
        sites = self._handle_py_ver_compat_for_input_str(param['sites_tokens'])

        summary = action_result.update_summary({})
        summary['hash'] = hash

        headers = self.HEADER
        headers["Authorization"] = "APIToken %s" % self.token
        headers["Content-Type"] = "application/json"

        # Fetch siteIds from siteToken
        site_ids = self._get_site_ids(sites, headers, action_result)

        if site_ids is None:
            return action_result.get_status()

        restrictions_url = self._base_url + self._api_v + "/restrictions"
        for site_id in site_ids:
            ids = []
            params = {"type": "black_hash", "siteIds": site_id, "value": hash}
            try:
                ret = requests.get(restrictions_url, headers=headers, params=params)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while getting restrictions : {0}".format(e))
            restrictions_data = ret.json().get('data', [])
            if restrictions_data:
                restriction = restrictions_data[0]
                restriction_id = restriction.get('id')
                if restriction_id:
                    ids.append(restriction_id)

        body = {
            "data": {
                "type": "black_hash",
                "ids": ids
            }
        }

        try:
            ret_val, _ = self._make_rest_call('/restrictions', action_result, headers=headers, method='delete', data=body)
            if (phantom.is_fail(ret_val)):
                return action_result.get_status()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while unblock hash: {0}".format(e))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_endpoints(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = "/agents"

        list_pgitems = self._list_pageitems(action_result, endpoint)

        if list_pgitems is None:
            return action_result.set_status(phantom.APP_ERROR, "Error while getting the endpoints")

        for item in list_pgitems:
            action_result.add_data(item)

        summary = action_result.update_summary({})
        summary['total_endpoints'] = len(list_pgitems)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_quarantine_device(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        ip_hostname = self._handle_py_ver_compat_for_input_str(param['ip_hostname'])
        sites = self._handle_py_ver_compat_for_input_str(param['sites_tokens'])

        try:
            ret_val = self._get_agent_id(ip_hostname, action_result)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while getting agent id : {0}".format(e))

        self.save_progress('Agent query: ' + ret_val)

        if (ret_val == '0'):
            return action_result.set_status(phantom.APP_ERROR, "Endpoint not found")
        elif (ret_val == '99'):
            return action_result.set_status(phantom.APP_ERROR, "More than one endpoint found")
        else:
            summary = action_result.update_summary({})
            summary['ip_hostname'] = ip_hostname
            summary['agent_id'] = ret_val

            headers = self.HEADER
            headers["Authorization"] = "APIToken %s" % self.token

            # Fetch siteIds from siteToken
            site_ids = self._get_site_ids(sites, headers, action_result)

            if site_ids is None:
                return action_result.get_status()

            body = {
                        "filter": {
                            "siteIds": site_ids,
                            "ids": [ret_val],
                        },
                    }
            try:
                ret_val, _ = self._make_rest_call('/agents/actions/disconnect', action_result, headers=headers, method='post', data=body)
                if (phantom.is_fail(ret_val)):
                    return action_result.get_status()
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while running quarantine device : {0}".format(e))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unquarantine_device(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        ip_hostname = self._handle_py_ver_compat_for_input_str(param['ip_hostname'])
        sites = self._handle_py_ver_compat_for_input_str(param['sites_tokens'])

        try:
            ret_val = self._get_agent_id(ip_hostname, action_result)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while getting agent ID : {0}".format(e))

        self.save_progress('Agent query: ' + ret_val)

        if (ret_val == '0'):
            return action_result.set_status(phantom.APP_ERROR, "Endpoint not found")
        elif (ret_val == '99'):
            return action_result.set_status(phantom.APP_ERROR, "More than one endpoint found")
        else:
            summary = action_result.update_summary({})
            summary['ip_hostname'] = ip_hostname
            summary['agent_id'] = ret_val

            headers = self.HEADER
            headers["Authorization"] = "APIToken %s" % self.token

            # Fetch siteIds from siteToken
            site_ids = self._get_site_ids(sites, headers, action_result)

            if site_ids is None:
                return action_result.get_status()

            body = {
                        "filter": {
                            "siteIds": site_ids,
                            "ids": [ret_val],
                        },
                    }

            try:
                ret_val, _ = self._make_rest_call('/agents/actions/connect', action_result, headers=headers, method='post', data=body)
                if (phantom.is_fail(ret_val)):
                    return action_result.get_status()
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while unquarantine device : {0}".format(e))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_scan_endpoint(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        ip_hostname = self._handle_py_ver_compat_for_input_str(param['ip_hostname'])
        sites = self._handle_py_ver_compat_for_input_str(param['sites_tokens'])

        try:
            ret_val = self._get_agent_id(ip_hostname, action_result)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while getting agent id : {0}".format(e))

        self.save_progress('Agent query: ' + ret_val)

        if ret_val == '0':
            return action_result.set_status(phantom.APP_ERROR, "Endpoint not found")
        elif ret_val == '99':
            return action_result.set_status(phantom.APP_ERROR, "More than one endpoint found")
        else:
            summary = action_result.update_summary({})
            summary['ip_hostname'] = ip_hostname
            summary['agent_id'] = ret_val

            headers = self.HEADER
            headers["Authorization"] = "APIToken %s" % self.token

            # Fetch siteIds from siteToken
            site_ids = self._get_site_ids(sites, headers, action_result)

            if site_ids is None:
                return action_result.get_status()

            body = {
                        "filter": {
                            "siteIds": site_ids,
                            "ids": [ret_val],
                        },
                    }

            try:
                ret_val, _ = self._make_rest_call('/agents/actions/initiate-scan', action_result, headers=headers, method='post', data=body)
                if (phantom.is_fail(ret_val)):
                    return action_result.get_status()
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while scanning endpoint : {0}".format(e))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_endpoint_info(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        ip_hostname = self._handle_py_ver_compat_for_input_str(param['ip_hostname'])

        try:
            ret_val = self._get_agent_id(ip_hostname, action_result)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while getting agent id : {0}".format(e))
        self.save_progress('Agent query: ' + ret_val)

        if ret_val == '0':
            return action_result.set_status(phantom.APP_ERROR, "Endpoint not found")
        elif ret_val == '99':
            return action_result.set_status(phantom.APP_ERROR, "More than one endpoint found")
        else:
            summary = action_result.update_summary({})
            summary['ip_hostname'] = ip_hostname
            summary['agent_id'] = ret_val

            # make rest call
            # GET /web/api/v1.6/agents/{id}
            headers = self.HEADER
            headers["Authorization"] = "APIToken %s" % self.token
            param = {"ids": ret_val}
            try:
                ret_val, response = self._make_rest_call('/agents', action_result, headers=headers, params=param)
                if (phantom.is_fail(ret_val)):
                    return action_result.get_status()
                self.save_progress("ret_val: {0}".format(ret_val))
            except Exception as ee:
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while getting endpoint info : {0}".format(ee))

        if not response.get('data'):
            return action_result.set_status(phantom.APP_ERROR, 'Found no details for the given endpoint')
        else:
            action_result.add_data(response.get('data')[0])
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_mitigate_threat(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        threat_id = self._handle_py_ver_compat_for_input_str(param['threat_id'])
        action = self._handle_py_ver_compat_for_input_str(param['action'])
        sites = self._handle_py_ver_compat_for_input_str(param['sites_tokens'])

        summary = action_result.update_summary({})
        summary['threat_id'] = threat_id
        summary['action'] = action

        headers = self.HEADER
        headers["Authorization"] = "APIToken %s" % self.token
        headers["Content-Type"] = "application/json"

        # Fetch siteIds from siteToken
        site_ids = self._get_site_ids(sites, headers, action_result)

        if site_ids is None:
            return action_result.get_status()

        body = {
                    "filter": {
                        "siteIds": site_ids,
                        "ids": [threat_id],
                    },
                }

        # POST /web/api/v2.1/threats/mitigate/:action
        try:
            ret_val, _ = self._make_rest_call('/threats/mitigate/' + action, action_result, headers=headers, method='post', data=body)
            if (phantom.is_fail(ret_val)):
                return action_result.get_status()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while mitigate threat : {0}".format(e))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _list_pageitems(self, action_result, endpoint):
        limit = 100
        cursor = None
        list_pgitems = list()
        headers = self.HEADER
        headers["Authorization"] = "APIToken %s" % self.token
        while True:
            params = dict()
            params['limit'] = limit
            if cursor is not None:
                params['cursor'] = cursor

            ret_val, response = self._make_rest_call(endpoint=endpoint, action_result=action_result, params=params, headers=headers)

            if phantom.is_fail(ret_val) or response is None:
                return None
            if response.get('data'):
                list_pgitems.extend(response.get('data'))

            if response.get('pagination').get('nextCursor') is None:
                break
            else:
                cursor = response.get('pagination').get('nextCursor')

        return list_pgitems

    def _handle_list_threats(self, param):
        # List the threats
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = "/threats"

        list_pgitems = self._list_pageitems(action_result, endpoint)

        if list_pgitems is None:
            return action_result.set_status(phantom.APP_ERROR, "Error while getting the threats")

        for threat in list_pgitems:
            action_result.add_data(threat)

        summary = action_result.update_summary({})
        summary['total_threats'] = len(list_pgitems)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_agent_id(self, search_text, action_result):
        # First lookup the Agent ID
        headers = self.HEADER
        headers["Authorization"] = "APIToken %s" % self.token
        param = {"query": search_text}
        ret_val, response = self._make_rest_call('/agents', action_result, headers=headers, params=param)

        if (phantom.is_fail(ret_val)):
            return str(-1)

        endpoints_found = len(response.get('data', []))
        self.save_progress("Endpoints found: " + str(endpoints_found))

        if endpoints_found == 0:
            return '0'
        elif endpoints_found > 1:
            return '99'
        else:
            return response.get('data')[0].get('id', str(-1))

    def handle_action(self, param=None, sites=None):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'list_endpoints':
            ret_val = self._handle_list_endpoints(param)

        elif action_id == 'get_endpoint_info':
            ret_val = self._handle_get_endpoint_info(param)

        elif action_id == 'block_hash':
            ret_val = self._handle_block_hash(param)

        elif action_id == 'quarantine_device':
            ret_val = self._handle_quarantine_device(param)

        elif action_id == 'unquarantine_device':
            ret_val = self._handle_unquarantine_device(param)

        elif action_id == 'unblock_hash':
            ret_val = self._handle_unblock_hash(param)

        elif action_id == 'mitigate_threat':
            ret_val = self._handle_mitigate_threat(param)

        elif action_id == 'scan_endpoint':
            ret_val = self._handle_scan_endpoint(param)

        elif action_id == 'list_threats':
            ret_val = self._handle_list_threats(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._python_version = int(sys.version_info[0])
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        # Access values in asset config by the name

        # Required values can be accessed directly
        self._base_url = self._handle_py_ver_compat_for_input_str(config['sentinelone_server_url'])

        # Optional values should use the .get() function
        self.token = self._handle_py_ver_compat_for_input_str(config.get('access_token'))

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-s', '--sites', help='sites', required=True)
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    sites_tokens = (args.sites).split(',')
    username = args.username
    password = args.password

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
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
            print("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    if len(sys.argv) < 2:
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SentineloneConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None, sites_tokens)
        print(json.dumps(json.loads(ret_val), indent=4))
