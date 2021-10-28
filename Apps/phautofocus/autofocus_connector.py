# File: autofocus_connector.py
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# pylint: disable=W0614,W0212,W0201,W0703,W0401,W0403

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Local imports
from autofocus_consts import *

from bs4 import UnicodeDammit
import sys
import simplejson as json
import requests
try:
    from urllib.parse import unquote
except:
    from urllib import unquote
import os
os.sys.path.insert(0, '{}/pan-python/lib'.format(os.path.dirname(os.path.abspath(__file__))))  # noqa
import pan.afapi  # noqa


# There is an error with python and requests. The pan API puts all the data into a dictionary,
#  then just calls 'requests.post(**kwargs)'. This will throw an exception, but explicitly taking out the url param and
#  doing the call like so fixes this
def patch_requests():
    requests_post_old = requests.post
    requests_get_old = requests.get

    # The only thing that should appear in *args (if request.post is being called correctly) is the url value
    def new_requests_post(*args, **kwargs):
        if 'url' in kwargs:
            url = kwargs.pop('url')
            return requests_post_old(url, **kwargs)
        return requests_post_old(*args, **kwargs)

    def new_requests_get(*args, **kwargs):
        if 'url' in kwargs:
            url = kwargs.pop('url')
            return requests_get_old(url, **kwargs)
        return requests_get_old(*args, **kwargs)

    requests.post = new_requests_post
    requests.get = new_requests_get


class AutoFocusConnector(BaseConnector):

    SCOPE_MAP = {'all samples': 'global', 'my samples': 'private', 'public samples': 'public'}
    # MAX_SIZE = 4000
    ACTION_ID_HUNT_FILE = "hunt_file"
    ACTION_ID_HUNT_IP = "hunt_ip"
    ACTION_ID_HUNT_DOMAIN = "hunt_domain"
    ACTION_ID_HUNT_URL = "hunt_url"
    ACTION_ID_GET_REPORT = "get_report"

    def __init__(self):
        super(AutoFocusConnector, self).__init__()

        self._afapi = None

    def initialize(self):
        # Fetching the Python major version
        self._state = self.load_state()

        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {
                "app_version": self.get_app_json().get('app_version')
            }
            return self.set_status(phantom.APP_ERROR, STATE_FILE_CORRUPT_ERR)

        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version")

        patch_requests()
        return phantom.APP_SUCCESS

    def finalize(self):
        """
        Perform some final operations or clean up operations.

        This function gets called once all the param dictionary elements are looped over and no more handle_action
        calls are left to be made. It gives the AppConnector a chance to loop through all the results that were
        accumulated by multiple handle_action function calls and create any summary if required. Another usage is
        cleanup, disconnect from remote devices etc.

        :return: status (success/failure)
        """
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.
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
                    error_code = ERR_CODE_MSG
                    error_msg = e.args[0]
            else:
                error_code = ERR_CODE_MSG
                error_msg = ERR_MSG_UNAVAILABLE
        except:
            error_code = ERR_CODE_MSG
            error_msg = ERR_MSG_UNAVAILABLE

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = TYPE_ERR_MSG
        except:
            error_msg = ERR_MSG_UNAVAILABLE

        try:
            if error_code in ERR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
        except:
            self.debug_print(PARSE_ERR_MSG)
            error_text = PARSE_ERR_MSG

        return error_text

    def _validate_api_call(self, response, action_result):
        """ Validate that an api call was successful """
        try:
            response.raise_for_status()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, self._get_error_message_from_exception(e))
        return phantom.APP_SUCCESS

    def _init_api(self, action_result):
        api_key = self.get_config()[AF_JSON_API_KEY]
        try:
            self._afapi = pan.afapi.PanAFapi(panrc_tag="autofocus", api_key=api_key)  # pylint: disable=E1101
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, self._get_error_message_from_exception(e))
        return phantom.APP_SUCCESS

    def _construct_body(self, value, field, start, size, scope="global"):
        body = {}
        body['scope'] = scope
        body['from'] = start
        body['size'] = size
        body['sort'] = {"create_date": {"order": "desc"}}
        body['query'] = {'operator': 'all', 'children': [{'field': field, 'operator': 'contains', 'value': value}]}
        return body

    def _samples_search_tag(self, body, action_result):
        """ Do a search specified by query and then create a list of tags """
        body = json.dumps(body)
        # This method calls both the /sample/search and the /sample/result
        #  endpoints, which is pretty nifty
        tag_set = set()
        try:
            # Truthfully I'm not sure what could cause either of these first two loops to iterate more than once
            # But they return lists so it must be possible somehow
            for r in self._afapi.samples_search_results(data=body):
                for i in r.json.get('hits', []):
                    if 'tag' in i.get('_source'):
                        for tag in i.get('_source', {}).get('tag', []):
                            tag_set.add(tag)

            for tag in tag_set:
                r = self._afapi.tag(tagname=tag)
                if not self._validate_api_call(r, action_result):
                    # Something wrong is going on if it reaches here
                    continue
                tag_data = {}
                tag_data['description'] = r.json.get('tag', {}).get('description')
                tag_data['tag_name'] = r.json.get('tag', {}).get('tag_name')
                tag_data['public_tag_name'] = r.json.get('tag', {}).get('public_tag_name')
                tag_data['count'] = r.json.get('tag', {}).get('count')
                action_result.add_data(tag_data)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, self._get_error_message_from_exception(e))

        action_result.update_summary({'total_tags_matched': action_result.get_data_size()})

        return phantom.APP_SUCCESS

    def _test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(param))

        self.save_progress("Starting connectivity test")
        ret_val = self._init_api(action_result)
        if phantom.is_fail(ret_val):
            return self.set_status_save_progress(phantom.APP_ERROR, "Connectivity test failed")

        # Now we need to send a command to test if creds are valid
        self.save_progress("Making a request to PAN AutoFocus")
        try:
            r = self._afapi.export()
            ret_val = self._validate_api_call(r, action_result)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, self._get_error_message_from_exception(e))
        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.save_progress("Connectivity test failed")
            return action_result.set_status(phantom.APP_ERROR)
        j = r.json['bucket_info']
        self.save_progress("{}/{} daily points remaining".format(j['daily_points_remaining'], j['daily_points']))
        return action_result.set_status(phantom.APP_SUCCESS, "Connectivity test passed")

    def _hunt_action(self, field, value_type, param):
        action_result = self.add_action_result(ActionResult(param))

        ret_val = self._init_api(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        scope = param.get(AF_JSON_SCOPE, 'All Samples').lower()
        try:
            scope = self.SCOPE_MAP[scope]
        except KeyError:
            # You can also just use "global", "private", or "public" if you want
            if scope in self.SCOPE_MAP.values():
                pass
            return action_result.set_status(phantom.APP_ERROR, AF_ERR_INVALID_SCOPE.format(scope))

        value = param[value_type]
        # start = int(param.get(AF_JSON_FROM, "0"))
        # size = int(param.get(AF_JSON_SIZE, "50"))
        start = 0
        size = 4000
        # This is not wrong. MAX_SIZE isn't the most entries you can retrieve,
        # but it is the largest index that you can retrieve form. from = 3999 and size = 2 would be invalid
        # if (start + size > self.MAX_SIZE):
        #     return action_result.set_status(phantom.APP_ERROR, AF_ERR_TOO_BIG.format(self.MAX_SIZE))
        body = self._construct_body(value, field, start, size, scope=scope)

        self.save_progress("Querying AutoFocus")
        ret_val = self._samples_search_tag(body, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _hunt_file(self, param):
        return self._hunt_action("alias.hash", AF_JSON_HASH, param)

    def _hunt_ip(self, param):
        return self._hunt_action("alias.ip_address", AF_JSON_IP, param)

    def _hunt_domain(self, param):
        return self._hunt_action("alias.domain", AF_JSON_DOMAIN, param)

    def _hunt_url(self, param):
        return self._hunt_action("alias.url", AF_JSON_URL, param)

    def _get_report(self, param):
        action_result = self.add_action_result(ActionResult(param))

        ret_val = self._init_api(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        tag = param[AF_JSON_TAG]

        try:
            r = self._afapi.tag(tagname=tag)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, unquote(self._get_error_message_from_exception(e)))
        ret_val = self._validate_api_call(r, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(r.json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved report info")

    def handle_action(self, param):
        action = self.get_action_identifier()
        ret_val = phantom.APP_SUCCESS

        if action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            ret_val = self._test_connectivity(param)
        elif action == self.ACTION_ID_HUNT_FILE:
            ret_val = self._hunt_file(param)
        elif action == self.ACTION_ID_HUNT_IP:
            ret_val = self._hunt_ip(param)
        elif action == self.ACTION_ID_HUNT_DOMAIN:
            ret_val = self._hunt_domain(param)
        elif action == self.ACTION_ID_HUNT_URL:
            ret_val = self._hunt_url(param)
        elif action == self.ACTION_ID_GET_REPORT:
            ret_val = self._get_report(param)

        return ret_val


if __name__ == '__main__':
    import pudb
    pudb.set_trace()
    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=' ' * 4))
        connector = AutoFocusConnector()
        connector.print_progress_message = True
        r_val = connector._handle_action(json.dumps(in_json), None)
        print(r_val)
    exit(0)
