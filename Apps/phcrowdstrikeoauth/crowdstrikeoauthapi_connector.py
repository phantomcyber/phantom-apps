# File: crowdstrikeoauthapi_connector.py
# Copyright (c) 2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# THIS Connector imports
from crowdstrikeoauthapi_consts import *

import requests
from bs4 import BeautifulSoup
import simplejson as json


class RetVal(tuple):

    def __new__(cls, val1, val2):

        return tuple.__new__(RetVal, (val1, val2))


class CrowdstrikeConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(CrowdstrikeConnector, self).__init__()

        self._state = {}
        self._base_url_oauth = None
        self._client_id = None
        self._client_secret = None
        self._oauth_access_token = None

    def initialize(self):
        """ Automatically called by the BaseConnector before the calls to the handle_action function"""

        config = self.get_config()

        # Base URL
        self._client_id = config[CROWDSTRIKE_CLIENT_ID].encode('utf-8')
        self._client_secret = config[CROWDSTRIKE_CLIENT_SECRET].encode('utf-8')
        self._base_url_oauth = config[CROWDSTRIKE_JSON_URL_OAuth].encode('utf-8')
        self._base_url_oauth = self._base_url_oauth.replace('\\', '/')

        if (self._base_url_oauth[-1] == '/'):
            self._base_url_oauth = self._base_url_oauth[:-1]

        self._state = self.load_state()
        self._oauth_access_token = self._state.get(CROWDSTRIKE_OAUTH_TOKEN_STRING, {}).get(CROWDSTRIKE_OAUTH_ACCESS_TOKEN_STRING)

        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _paginator(self, action_result, endpoint, param):
        """
        This action is used to create an iterator that will paginate through responses from called methods.

        :param method_name: Name of method whose response is to be paginated
        :param action_result: Object of ActionResult class
        :param **kwargs: Dictionary of Input parameters
        """

        list_ids = list()

        limit = None
        if param.get('limit'):
            limit = param.pop('limit')

        offset = 0

        while True:

            param.update({"offset": offset})
            ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, params=param)

            if phantom.is_fail(ret_val):
                return None

            offset = response.get('meta', {}).get("pagination", {}).get("offset")
            total = response.get('meta', {}).get("pagination", {}).get("total")

            if offset is None or total is None:
                return action_result.set_status(phantom.APP_ERROR, "Error occurred in fetching 'offset' and 'total' key-values while fetching paginated results")

            if response.get("resources"):
                list_ids.extend(response.get("resources"))

            if limit and len(list_ids) >= limit:
                return list_ids[:limit]

            if offset == total:
                return list_ids

        return list_ids

    def _test_connectivity_oauth2(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # initially set the token for first time
        ret_val = self._get_token(action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if not param:
            param = {}

        param.update({'limit': 1})

        ret_val, resp_json = self._make_rest_call_helper_oauth2(action_result, CROWDSTRIKE_GET_DEVICE_ID_ENDPOINT, params=param)

        if (phantom.is_fail(ret_val)):
            self.save_progress(CROWDSTRIKE_ERR_CONNECTIVITY_TEST)
            return phantom.APP_ERROR

        return self.set_status_save_progress(phantom.APP_SUCCESS, CROWDSTRIKE_SUCC_CONNECTIVITY_TEST)

    def _get_ids(self, action_result, endpoint, param):

        limit = param.get("limit")

        if (limit and not str(limit).isdigit()) or limit == 0:
            action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_INVALID_LIMIT)
            return None

        id_list = self._paginator(action_result, endpoint, param)

        if id_list is None:
            return id_list

        id_list = map(str, id_list)

        return id_list

    def _get_details(self, action_result, endpoint, param):

        list_ids = param.get("ids")

        list_ids_details = list()

        while list_ids:
            param = {"ids": list_ids[:min(100, len(list_ids))]}
            ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, params=param)

            if phantom.is_fail(ret_val):
                return None

            if response.get("resources"):
                list_ids_details.extend(response.get("resources"))

            del list_ids[:min(100, len(list_ids))]

        return list_ids_details

    def _handle_query_device(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_id_list = self._get_ids(action_result, CROWDSTRIKE_GET_DEVICE_ID_ENDPOINT, param)

        if device_id_list is None:
            return action_result.get_status()

        if device_id_list:
            param.update({"ids": device_id_list})

            device_details_list = self._get_details(action_result, CROWDSTRIKE_GET_DEVICE_DETAILS_ENDPOINT, param)

            if device_details_list is None:
                return action_result.get_status()

            for device in device_details_list:
                action_result.add_data(device)

        summary = action_result.update_summary({})
        summary['total_devices'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_groups(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        host_group_id_list = self._get_ids(action_result, CROWDSTRIKE_GET_HOST_GROUP_ID_ENDPOINT, param)

        if host_group_id_list is None:
            return action_result.get_status()

        if host_group_id_list:
            param.update({"ids": host_group_id_list})

            host_group_details_list = self._get_details(action_result, CROWDSTRIKE_GET_HOST_GROUP_DETAILS_ENDPOINT, param)

            if host_group_details_list is None:
                return action_result.get_status()

            for host_group in host_group_details_list:
                action_result.add_data(host_group)

        summary = action_result.update_summary({})
        summary['total_host_groups'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _check_params(self, action_result, param):

        ids = list()
        device_id = param.get("device_id")
        hostname = param.get("hostname")
        device_id_flag, hostname_flag = False, False
        intermediate_device_ids = list()

        if not device_id and not hostname:
            return action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_NO_PARAMETER_ERROR), None

        if device_id:
            device_ids = [x.strip() for x in device_id.split(',')]
            device_ids = ' '.join(device_ids).split()
            if len(device_ids) == 0:
                return action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_INVALID_INPUT_ERROR), None

            ret_val, device_id_flag, interim_devices_list = self._set_error_flag_inputs(action_result, device_ids, "device_id")

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            intermediate_device_ids.extend(interim_devices_list)

        if hostname:
            hostnames = [x.strip() for x in hostname.split(',')]
            hostnames = ' '.join(hostnames).split()
            if len(hostnames) == 0:
                return action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_INVALID_INPUT_ERROR), None

            ret_val, hostname_flag, interim_hostnames_list = self._set_error_flag_inputs(action_result, hostnames, "hostname")

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            intermediate_device_ids.extend(interim_hostnames_list)

        if device_id_flag and hostname_flag:
            return action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_INVALID_DEVICE_ID_AND_HOSTNAME_ERROR), None
        elif device_id_flag:
            return action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_INVALID_DEVICE_ID_ERROR), None
        elif hostname_flag:
            return action_result.set_status(phantom.APP_ERROR, CROWDSTRIKE_INVALID_HOSTNAME_ERROR), None
        else:
            ids.extend(intermediate_device_ids)

        return action_result.set_status(phantom.APP_SUCCESS), list(set(ids))

    def _set_error_flag_inputs(self, action_result, list_items, key):

        flag = False
        check_list_items = list()
        filter = ""

        for item in list_items:
            filter = "{f}{key}: '{item}', ".format(f=filter, key=key, item=item)  # or opeartion with given hostname/s
        filter = filter[:-2]   # removing last trailing , and space

        check_list_items = self._get_ids(action_result, CROWDSTRIKE_GET_DEVICE_ID_ENDPOINT, param={"filter": filter})

        if check_list_items is None:
            return action_result.get_status(), flag, []

        if len(list_items) != len(check_list_items):
            flag = True
            check_list_items = []

        return phantom.APP_SUCCESS, flag, check_list_items

    def _perform_device_action(self, action_result, param):

        count = 0

        ret_val, list_ids = self._check_params(action_result, param)

        if phantom.is_fail(ret_val):
            msg = action_result.get_message()
            if "Invalid filter expression supplied" in msg:
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while validating given input parameters. Error : {}".format(msg))
            return action_result.get_status()

        if not list_ids:
            return action_result.set_status(phantom.APP_ERROR, "No correct device IDs could be found for the provided input parameters values")

        data = {}
        endpoint = None
        count = len(list_ids)

        action_name = param.get("action_name")
        params = {"action_name": action_name}

        if action_name == "contain" or action_name == "lift_containment":

            endpoint = CROWDSTRIKE_DEVICE_ACTION_ENDPOINT

            while list_ids:

                data = {"ids": list_ids[:min(100, len(list_ids))]}

                ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, params=params, data=json.dumps(data), method="post")

                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                if not response.get("resources"):
                    return action_result.set_status(phantom.APP_ERROR, "No action could be performed on the provided devices")

                for device in response.get("resources"):
                    action_result.add_data(device)

                del list_ids[:min(100, len(list_ids))]

            summary = action_result.update_summary({})

            if action_name == "contain":
                summary['total_quarantined_device'] = action_result.get_data_size()
            elif action_name == "lift_containment":
                summary['total_unquarantined_device'] = action_result.get_data_size()

            return phantom.APP_SUCCESS

        elif action_name == "add-hosts" or action_name == "remove-hosts":

            endpoint = CROWDSTRIKE_GROUP_DEVICE_ACTION_ENDPOINT

            while list_ids:
                data = {
                    "action_parameters": [{
                        "name": "filter",
                        "value": "(device_id:{})".format(str(list_ids[:min(100, len(list_ids))]))
                    }],
                    "ids": [
                            param.get("host_group_id")
                    ]
                }

                ret_val, response = self._make_rest_call_helper_oauth2(action_result, endpoint, params=params, data=json.dumps(data), method="post")

                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                del list_ids[:min(100, len(list_ids))]

            if not response.get("resources"):
                return action_result.set_status(phantom.APP_ERROR, "No action could be performed on the provided devices")

            for device in response.get("resources"):
                action_result.add_data(device)

            summary = action_result.update_summary({})

            if action_name == "add-hosts":
                summary['total_assigned_device'] = count
            elif action_name == "remove-hosts":
                summary['total_removed_device'] = count

            return phantom.APP_SUCCESS

        else:
            return action_result.set_status(phantom.APP_ERROR, "Incorrect action name")

    def _handle_quarantine_device(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not param:
            param = {}

        param["action_name"] = "contain"

        ret_val = self._perform_device_action(action_result, param)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unquarantine_device(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not param:
            param = {}

        param["action_name"] = "lift_containment"

        ret_val = self._perform_device_action(action_result, param)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_assign_hosts(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not param:
            param = {}

        param["action_name"] = "add-hosts"

        ret_val = self._perform_device_action(action_result, param)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_remove_hosts(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not param:
            param = {}

        param["action_name"] = "remove-hosts"

        ret_val = self._perform_device_action(action_result, param)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _process_empty_response(self, response, action_result):
        """ This function is used to process empty response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if response.status_code == 200 or response.status_code == 202:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"),
                      None)

    def _process_html_response(self, response, action_result):
        """ This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # An html response, treat it like an error
        status_code = response.status_code

        if status_code == 400:
            message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, CROWDSTRIKE_HTML_ERROR)

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text.encode('utf-8')
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        if len(message) > 500:
            message = 'Error occured while connecting to the CrowdStrike server'

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, response, action_result):
        """ This function is used to process json response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # Try a json parse
        try:
            resp_json = response.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".
                                                   format(str(e))), None)

        # Please specify the status codes here
        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = "Error from server. Status Code: {0} Data from server: {1}".format(response.status_code,
                                                                                     response.text.replace('{', '{{')
                                                                                     .replace('}', '}}').encode('utf-8'))

        # Show only error message if available
        if isinstance(resp_json.get('errors', []), list):
            msg = ""
            for error in resp_json.get('errors', []):
                msg = "{} {}".format(msg, error.get('message').encode('utf-8'))
            message = "Error from server. Status Code: {0} Data from server: {1}".format(response.status_code, msg)
        else:
            message = "Error from server. Status Code: {0}".format(response.status_code)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, response, action_result):
        """ This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': response.status_code})
            action_result.add_debug_data({'r_text': response.text})
            action_result.add_debug_data({'r_headers': response.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response, action_result)

        if 'text/javascript' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response, action_result)

        # Process an HTML response, Do this no matter what the API talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in response.headers.get('Content-Type', ''):
            return self._process_html_response(response, action_result)

        # Reset_password returns empty body
        if not response.text and 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, {})

        # it's not content-type that is to be parsed, handle an empty response
        if not response.text:
            return self._process_empty_response(response, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            response.status_code, response.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call_oauth2(self, endpoint, action_result, headers=None, params=None, data=None, json=None, method="get"):
        """ Function that makes the REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        try:
            r = request_func(endpoint, json=json, data=data, headers=headers, params=params)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error connecting to server. Details: {0}"
                                                   .format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _make_rest_call_helper_oauth2(self, action_result, endpoint, headers=None, params=None, data=None, json=None, method="get"):
        """ Function that helps setting REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        url = "{0}{1}".format(self._base_url_oauth, endpoint)
        if (headers is None):
            headers = {}

        token = self._state.get('oauth2_token', {})
        if not token.get('access_token'):
            ret_val = self._get_token(action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

        headers.update({
                'Authorization': 'Bearer {0}'.format(self._oauth_access_token),
                'Content-Type': 'application/json'
            })

        ret_val, resp_json = self._make_rest_call_oauth2(url, action_result, headers, params, data, json, method)

        # If token is expired, generate a new token
        msg = action_result.get_message()
        if msg and 'token is invalid' in msg or 'token has expired' in msg or 'ExpiredAuthenticationToken' in msg or 'authorization failed' in msg or 'access denied ' in msg:
            ret_val = self._get_token(action_result)

            headers.update({ 'Authorization': 'Bearer {0}'.format(self._oauth_access_token)})

            ret_val, resp_json = self._make_rest_call_oauth2(url, action_result, headers, params, data, json, method)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, resp_json

    def _get_token(self, action_result, from_action=False):
        """ This function is used to get a token via REST Call.

        :param action_result: Object of action result
        :param from_action: Boolean object of from_action
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        data = {
            'client_id': self._client_id,
            'client_secret': self._client_secret
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }

        url = "{}{}".format(self._base_url_oauth, CROWDSTRIKE_OAUTH_TOKEN_ENDPOINT)

        ret_val, resp_json = self._make_rest_call_oauth2(url, action_result, headers=headers, data=data, method='post')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        self._state[CROWDSTRIKE_OAUTH_TOKEN_STRING] = resp_json
        self._oauth_access_token = resp_json[CROWDSTRIKE_OAUTH_ACCESS_TOKEN_STRING]
        self.save_state(self._state)

        return phantom.APP_SUCCESS

    def handle_action(self, param):

        # Get the action that we are supposed to execute for this App Run
        self.debug_print("action_id ", self.get_action_identifier())

        action_mapping = {
            'test_asset_connectivity': self._test_connectivity_oauth2,
            'query_device': self._handle_query_device,
            'list_groups': self._handle_list_groups,
            'quarantine_device': self._handle_quarantine_device,
            'unquarantine_device': self._handle_unquarantine_device,
            'remove_hosts': self._handle_remove_hosts,
            'assign_hosts': self._handle_assign_hosts
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping.keys():
            action_function = action_mapping[action]
            action_execution_status = action_function(param)

        return action_execution_status


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
            print ("Accessing the Login page")
            r = requests.get(BaseConnector._get_phantom_base_url() + "login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = BaseConnector._get_phantom_base_url() + 'login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post(BaseConnector._get_phantom_base_url() + "login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CrowdstrikeConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
