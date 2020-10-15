# File: mimecast_connector.py
# Copyright (c) 2019-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from mimecast_consts import *
import requests
import json
from bs4 import BeautifulSoup
import uuid
import base64
import hmac
import datetime
import dateutil.parser
import hashlib
import sys
from bs4 import UnicodeDammit


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class MimecastConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(MimecastConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _login(self, action_result):
        uri = '/api/login/login'
        auth_type = 'Basic-AD' if self._auth_type == 'Domain' else 'Basic-Cloud'
        try:
            encoded_auth_token = base64.b64encode(('{0}:{1}').format(self._username, self._password))
        except:
            # In Python v3, strings are not binary,
            # so we need to explicitly convert them to 'bytes' (which are binary)
            # We need to convert 'bytes' back to string,
            # as the contents of headers are of the 'string' form
            encoded_auth_token = base64.b64encode(bytes(('{0}:{1}').format(self._username, self._password), 'utf-8')).decode('utf-8')
        headers = {'Authorization': auth_type + ' ' + encoded_auth_token,
           'x-mc-app-id': self._app_id,
           'x-mc-date': datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S') + ' UTC',
           'x-mc-req-id': str(uuid.uuid4()),
           'Content-Type': 'application/json'}
        body = {'data': [
                  {'userName': self._username}]}
        ret_val, response = self._make_rest_call(uri, action_result, data=body, headers=headers, method='post')

        if phantom.is_fail(ret_val):
            return action_result.get_status()
        self.save_progress('Login successful')
        self._access_key = response['data'][0]['accessKey']
        self._secret_key = response['data'][0]['secretKey']
        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully set accessKey and secretKey")

    def _get_request_headers(self, uri, action_result, expired=False):
        if self._access_key is None or self._secret_key is None:
            self._login(action_result)
            if action_result.get_status() is False:
                self.save_progress("Failed login with given credentials")
                return None
        else:
            self.save_progress("Skipped login")
        request_id = str(uuid.uuid4())
        hdr_date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S') + ' UTC'
        # The 'hmac' library on Python v3 expects the parameters in bytes (or binary format),
        # while the 'hmac' library on Python v3 expects the parameters in string
        # (which are stored in binary and Unicode form on Python v2 and Python v3 respectively).
        # UnicodeDammit.unicode_markup.encode() works for both the versions, as it converts the
        # provided input to string on Python v2 and bytes on Python v3.
        encoded_secret_key = UnicodeDammit(self._secret_key).unicode_markup.encode("utf-8")
        encoded_msg = UnicodeDammit(':'.join([hdr_date, request_id, uri, self._app_key])).unicode_markup.encode("utf-8")
        hmac_sha1 = hmac.new(base64.b64decode(encoded_secret_key), encoded_msg, digestmod=hashlib.sha1).digest()
        sig = base64.encodestring(hmac_sha1).rstrip()
        # For Python v3 'bytes' need to be converted back to 'string'
        # as the contents of headers are of the 'string' form
        decoded_sig = UnicodeDammit(sig).unicode_markup
        headers = {'Authorization': 'MC ' + self._access_key + ':' + decoded_sig,
           'x-mc-app-id': self._app_id,
           'x-mc-date': hdr_date,
           'x-mc-req-id': request_id,
           'Content-Type': 'application/json'}
        return headers

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR,
        "Empty response and no information in the header. Please check the asset configuration and|or action parameters."), None)

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
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(self._get_error_message_from_exception(e))), None)

        # Please specify the status codes here
        if not resp_json['fail']:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Message from server: {0} ".format(resp_json['fail'][0]['errors'][0]['message'])

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
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _validate_integers(self, action_result, parameter, key, allow_zero=False):
        """ This method is to check if the provided input parameter value
        is a non-zero positive integer and returns the integer value of the parameter itself.
        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :return: integer value of the parameter or None in case of failure
        """

        try:
            if not float(parameter).is_integer():
                action_result.set_status(phantom.APP_ERROR, "Please provide a valid integer value in the {} parameter".format(key))
                return None
            parameter = int(parameter)

            if not allow_zero and parameter <= 0:
                action_result.set_status(phantom.APP_ERROR, "Please provide a valid non-zero positive integer value in the {parameter} parameter".format(parameter=key))
                return None
            elif allow_zero and parameter < 0:
                action_result.set_status(phantom.APP_ERROR, "Please provide zero or a valid positive integer value in the {parameter} parameter".format(parameter=key))
                return None
        except:
            error_text = "Please provide zero or a valid positive integer value in the {parameter} parameter".format(parameter=key) if allow_zero else\
                 "Please provide a valid non-zero positive integer value in the {parameter} parameter".format(parameter=key)
            action_result.set_status(phantom.APP_ERROR, error_text)
            return None

        return parameter

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.
        :param python_version: Python major version
        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """

        try:
            if input_str and self._python_version == 2:
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

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
            error_msg = "Error occurred while connecting to the Mimecast server. Please check the asset configuration and|or the action parameters."
        except:
            error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _paginator(self, endpoint, action_result, limit=None, headers=None, data=None, method="get", **kwargs):

        default_max_results = 100
        page_size = default_max_results
        # If page_size param is present, then validate if pageSize is a positive integer greater than zero
        data_object = {}

        if limit is not None:
            # Validate pageSize is a positive integer greater than zero
            try:
                limit = int(limit)
                if limit <= 0:
                    return action_result.set_status(phantom.APP_ERROR, "Page size value must be an integer greater than 0")
            except:
                return action_result.set_status(phantom.APP_ERROR, "Page size value must be an integer greater than 0")
            page_size = min(page_size, limit)

        data_object['pageSize'] = page_size
        data['meta']['pagination'].update(data_object)

        response = {}
        count = 0

        while True:

            ret_val, interim_response = self._make_rest_call_helper(endpoint, action_result, headers=headers, method=method, data=data, **kwargs)

            if phantom.is_fail(ret_val):
                return ret_val, interim_response

            if response:
                response['meta'].update(interim_response['meta'])
                response['fail'].extend(interim_response['fail'])
                for key, val in list(interim_response['data'][0].items()):
                    if isinstance(val, list):
                        response['data'][0][key].extend(val)
                    else:
                        response['data'][0][key] = val
            else:
                response = interim_response
            count += interim_response['meta']['pagination']['pageSize']
            if limit:
                if count == limit:
                    break
                if count + page_size > limit:
                    data['meta']['pagination']['pageSize'] = limit - count

            nextToken = interim_response['meta']['pagination'].get('next')

            if nextToken:
                data['meta']['pagination']['pageToken'] = nextToken
            else:
                break

        return ret_val, response

    def _make_rest_call_helper(self, endpoint, action_result, headers=None, params=None, data=None, method="get", **kwargs):

        ret_val, response = self._make_rest_call(endpoint, action_result, headers, params, data, method, **kwargs)

        if not phantom.is_fail(ret_val):
            ret_val, response

        # If token is expired, generate a new token
        msg = action_result.get_message()

        if "AccessKey Has Expired" in msg:
            # Resetting the access_key and secret_key to None
            # will generate new access_key and secret_key.
            self._access_key = None
            self._secret_key = None
            headers = self._get_request_headers(endpoint, action_result)

            if headers is None:
                return action_result.get_status(), None

            ret_val, response = self._make_rest_call(endpoint, action_result, headers, params, data, method, **kwargs)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return ret_val, response

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get", **kwargs):

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
                            headers=headers,
                            json=data,
                            verify=config.get('verify_server_cert', False),
                            params=params)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to the Mimecast server. Details: {0}"
                        .format(self._get_error_message_from_exception(e))), resp_json)
        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        uri = '/api/ttp/url/get-all-managed-urls'
        self._access_key = None
        self._secret_key = None
        headers = self._get_request_headers(uri, action_result)
        if headers is None:
            self.save_progress("Test Connectivity Failed")
            return action_result.set_status(phantom.APP_ERROR)
        data = {'data': []}

        self.save_progress('Querying endpoint')
        ret_val, response = self._make_rest_call(uri, action_result, params=None, headers=headers, method="post", data=data)
        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress('Test Connectivity Passed')
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_blacklist_url(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        uri = '/api/ttp/url/create-managed-url'
        headers = self._get_request_headers(uri=uri, action_result=action_result)

        # Flipping logic to make 'enable' checkboxes for better UX
        if param.get("enable_log_click"):
            log_click = False
        else:
            log_click = True

        data = {
            "data": [
                {
                    "comment": param.get("comment"),
                    "url": param.get("url"),
                    "disableLogClick": log_click,
                    "action": "block",
                    "matchType": param.get("match_type", "explicit")
                }
            ]
        }

        ret_val, response = self._make_rest_call_helper(uri, action_result, headers=headers, method="post", data=data)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response['data'][0])

        summary = action_result.update_summary({})
        summary['status'] = "Successfully added URL to blacklist"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_remove_url(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        uri = '/api/ttp/url/delete-managed-url'
        headers = self._get_request_headers(uri=uri, action_result=action_result)

        data = {
            "data": [
                {
                    "id": param.get("id")
                }
            ]
        }

        ret_val, response = self._make_rest_call_helper(uri, action_result, headers=headers, method="post", data=data)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response['data'])

        summary = action_result.update_summary({})
        summary['status'] = "Successfully removed URL from URL Protection List"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_whitelist_url(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        uri = '/api/ttp/url/create-managed-url'
        headers = self._get_request_headers(uri=uri, action_result=action_result)

        # Flipping logic to make 'enable' checkboxes for better UX
        if param.get("enable_log_click"):
            log_click = False
        else:
            log_click = True

        if param.get("enable_rewrite"):
            rewrite = False
        else:
            rewrite = True

        if param.get("enable_user_awareness"):
            user_awareness = False
        else:
            user_awareness = True

        data = {
            "data": [
                {
                    "comment": param.get("comment"),
                    "disableRewrite": rewrite,
                    "url": param.get("url"),
                    "disableUserAwareness": user_awareness,
                    "disableLogClick": log_click,
                    "action": "permit",
                    "matchType": param.get("match_type", "explicit")
                }
            ]
        }

        ret_val, response = self._make_rest_call_helper(uri, action_result, headers=headers, method="post", data=data)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response['data'][0])

        summary = action_result.update_summary({})
        summary['status'] = "Successfully added URL to whitelist"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_member(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        uri = '/api/directory/add-group-member'
        headers = self._get_request_headers(uri=uri, action_result=action_result)

        data = {
            "data": [
                {
                    "id": param.get("id")
                }
            ]
        }

        data_object = {}
        member = param.get("member")

        if phantom.is_domain(member):
            data_object['domain'] = member
        elif phantom.is_email(member):
            data_object['emailAddress'] = member

        if data_object:
            data['data'][0].update(data_object)

        ret_val, response = self._make_rest_call_helper(uri, action_result, headers=headers, method="post", data=data)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response['data'][0])

        summary = action_result.update_summary({})
        summary['status'] = "Successfully added member to group"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_remove_member(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        uri = '/api/directory/remove-group-member'
        headers = self._get_request_headers(uri=uri, action_result=action_result)

        data = {
            "data": [
                {
                    "id": param.get("id")
                }
            ]
        }

        data_object = {}
        member = param.get("member")

        if phantom.is_domain(member):
            data_object['domain'] = member
        elif phantom.is_email(member):
            data_object['emailAddress'] = member

        if data_object:
            data['data'][0].update(data_object)

        ret_val, response = self._make_rest_call_helper(uri, action_result, headers=headers, method="post", data=data)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response['data'][0])

        summary = action_result.update_summary({})
        summary['status'] = "Successfully removed member from group"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_blacklist_sender(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        uri = '/api/managedsender/permit-or-block-sender'
        headers = self._get_request_headers(uri=uri, action_result=action_result)

        action_id = self.get_action_identifier()
        action = None

        if action_id == 'blacklist_sender':
            action = 'block'
        else:
            action = 'permit'

        data = {
            "data": [
                {
                    "sender": param.get("sender"),
                    "to": param.get("to"),
                    "action": action
                }
            ]
        }

        ret_val, response = self._make_rest_call_helper(uri, action_result, headers=headers, method="post", data=data)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response['data'][0])

        summary = action_result.update_summary({})
        summary['status'] = "Successful {0}".format(action)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_urls(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        uri = '/api/ttp/url/get-all-managed-urls'
        headers = self._get_request_headers(uri=uri, action_result=action_result)

        data = {
            'meta': {
                'pagination': {
                    'pageSize': 100
                }
            },
            'data': [
            ]
        }

        ret_val, response = self._paginator(uri, action_result, headers=headers, method="post", data=data)

        if phantom.is_fail(ret_val):
            return ret_val

        for url in response['data']:
            action_result.add_data(url)

        summary = action_result.update_summary({})
        summary['num_urls'] = len(response['data'])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_groups(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        uri = '/api/directory/find-groups'
        headers = self._get_request_headers(uri=uri, action_result=action_result)

        data = {
            'meta': {
                'pagination': {
                    'pageToken': param.get('page_token')
                }
            },
            'data': [
            ]
        }

        # Build request body params one by one. These params are optional
        data_object = {}

        if param.get('query') is not None:
            data_object['query'] = param.get('query')

        if param.get('source') is not None:
            data_object['source'] = param.get('source')

        if data_object:
            data['data'].append(data_object)

        limit = param.get('page_size')
        if limit is not None:
            limit = self._validate_integers(action_result, limit, "page_size")
            if limit is None:
                return action_result.get_status()

        ret_val, response = self._paginator(uri, action_result, limit=limit, headers=headers, method="post", data=data)

        if phantom.is_fail(ret_val):
            return ret_val

        response['groups'] = response.pop('data')

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['num_groups'] = len(response['groups'][0]['folders'])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_members(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        uri = '/api/directory/get-group-members'
        headers = self._get_request_headers(uri=uri, action_result=action_result)

        data = {
            'meta': {
                'pagination': {
                    'pageToken': param.get('page_token')
                }
            },
            'data': [
                {
                    'id': param.get('id')
                }
            ]
        }

        limit = param.get('page_size')
        if limit is not None:
            limit = self._validate_integers(action_result, limit, "page_size")
            if limit is None:
                return action_result.get_status()

        ret_val, response = self._paginator(uri, action_result, limit=limit, headers=headers, method="post", data=data)

        if phantom.is_fail(ret_val):
            return ret_val

        response['members'] = response.pop('data')

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['num_group_members'] = len(response['members'][0]['groupMembers'])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_find_member(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        uri = '/api/directory/get-group-members'
        headers = self._get_request_headers(uri=uri, action_result=action_result)
        member = param.get('member')
        type_list = ['email', 'domain']
        search_type = self._handle_py_ver_compat_for_input_str(param['type'])
        if search_type:
            if search_type not in type_list:
                return action_result.set_status(phantom.APP_ERROR, "Please provide a valid value in the 'type' parameter")
        if search_type == 'email':
            search_type = 'emailAddress'

        # Mimecast API only returns a maximum of 100 results. Looping is needed for groups with 100+ members
        while True:

            data = {
                'meta': {
                    'pagination': {
                        'pageToken': param.get('page_token'),
                        'pageSize': 100
                    }
                },
                'data': [
                    {
                        'id': param.get('id')
                    }
                ]
            }

            ret_val, response = self._make_rest_call_helper(uri, action_result, headers=headers, method="post", data=data)

            if phantom.is_fail(ret_val):
                return ret_val

            response['members'] = response.pop('data')

            groupMembers = response['members'][0]['groupMembers']
            nextToken = response['meta']['pagination'].get('next')

            # Successful if member found, fails if nextToken does not exist, repeats loop if nextToken exists
            if any(i[search_type] == member for i in groupMembers):
                summary = action_result.update_summary({})
                summary['status'] = "Found Member!"
                return action_result.set_status(phantom.APP_SUCCESS)
            elif nextToken is None:
                summary = action_result.update_summary({})
                summary['status'] = "Member does not exist."
                return action_result.set_status(phantom.APP_ERROR)
            else:
                param['page_token'] = nextToken

    def _handle_run_query(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        uri = '/api/message-finder/search'
        headers = self._get_request_headers(uri=uri, action_result=action_result)

        data = {
            "data": [
                {
                    "searchReason": param.get("search_reason"),
                    "messageId": param.get("message_id"),
                    "advancedTrackAndTraceOptions": {
                        "from": param.get("from"),
                        "to": param.get("to"),
                        "subject": param.get("subject"),
                        "senderIP": param.get("sender_ip")
                    }
                }
            ]
        }

        # Check to see if both timestamps are in valid format
        if param.get('start') is not None:
            start = param.get('start')
            try:
                start = dateutil.parser.parse(start)
                start = start.strftime('%Y-%m-%dT%H:%M:%S+%f')[:-2]
            except Exception as e:
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Start timestamp format should be YYYY-MM-DDTHH:MM:SS+0000 Error: {0}".format(
                    self._get_error_message_from_exception(e))), None)
        if param.get('end') is not None:
            end = param.get('end')
            try:
                end = dateutil.parser.parse(end)
                end = end.strftime('%Y-%m-%dT%H:%M:%S+%f')[:-2]
            except Exception as e:
                return RetVal(action_result.set_status(phantom.APP_ERROR, "End timestamp format should be YYYY-MM-DDTHH:MM:SS+0000 Error: {0}".format(
                    self._get_error_message_from_exception(e))), None)

        # Add timestamps to payload
        data_object = {}

        if param.get('start') is not None:
            data_object['start'] = start

        if param.get('end') is not None:
            data_object['end'] = end

        if data_object:
            data['data'][0].update(data_object)

        ret_val, response = self._make_rest_call_helper(uri, action_result, headers=headers, method="post", data=data)

        if phantom.is_fail(ret_val):
            return ret_val

        for email in response['data'][0]['trackedEmails']:
            action_result.add_data(email)

        summary = action_result.update_summary({})
        summary['num_emails'] = len(response['data'][0]['trackedEmails'])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_email(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        uri = '/api/message-finder/get-message-info'
        headers = self._get_request_headers(uri=uri, action_result=action_result)

        data = {
            "data": [
                {
                    "id": self._handle_py_ver_compat_for_input_str(param.get("id"))
                }
            ]
        }

        ret_val, response = self._make_rest_call_helper(uri, action_result, headers=headers, method="post", data=data)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response['data'][0])

        summary = action_result.update_summary({})
        summary['status'] = "Successfully retrieved message information"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_decode_url(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        uri = '/api/ttp/url/decode-url'
        headers = self._get_request_headers(uri=uri, action_result=action_result)

        data = {
            "data": [
                {
                    "url": param.get("url")
                }
            ]
        }

        ret_val, response = self._make_rest_call_helper(uri, action_result, headers=headers, method="post", data=data)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response['data'][0])

        summary = action_result.update_summary({})
        summary['status'] = "Successfully decoded URL"

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'blacklist_url':
            ret_val = self._handle_blacklist_url(param)

        elif action_id == 'unblacklist_url':
            ret_val = self._handle_remove_url(param)

        elif action_id == 'whitelist_url':
            ret_val = self._handle_whitelist_url(param)

        elif action_id == 'unwhitelist_url':
            ret_val = self._handle_remove_url(param)

        elif action_id == 'add_member':
            ret_val = self._handle_add_member(param)

        elif action_id == 'remove_member':
            ret_val = self._handle_remove_member(param)

        elif action_id == 'blacklist_sender':
            ret_val = self._handle_blacklist_sender(param)

        elif action_id == 'whitelist_sender':
            ret_val = self._handle_blacklist_sender(param)

        elif action_id == 'list_urls':
            ret_val = self._handle_list_urls(param)

        elif action_id == 'list_groups':
            ret_val = self._handle_list_groups(param)

        elif action_id == 'list_members':
            ret_val = self._handle_list_members(param)

        elif action_id == 'find_member':
            ret_val = self._handle_find_member(param)

        elif action_id == 'run_query':
            ret_val = self._handle_run_query(param)

        elif action_id == 'get_email':
            ret_val = self._handle_get_email(param)

        elif action_id == 'decode_url':
            ret_val = self._handle_decode_url(param)

        return ret_val

    def initialize(self):
        self._state = self.load_state()

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version.")

        config = self.get_config()
        self._base_url = config['base_url'].rstrip('/')
        self._username = self._handle_py_ver_compat_for_input_str(config['username'])
        self._password = config['password']
        self._app_id = config['app_id']
        self._app_key = config['app_key']
        self._auth_type = config['auth_type']
        self._access_key = self._state.get('access_key')
        self._secret_key = self._state.get('secret_key')

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self._state['access_key'] = self._access_key
        self._state['secret_key'] = self._secret_key
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
            print("Accessing the Login page")
            login_url = BaseConnector._get_phantom_base_url() + 'login'
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

        connector = MimecastConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
