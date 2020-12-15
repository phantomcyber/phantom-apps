# File: consolidatedscreeninglist_connector.py
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)


from __future__ import print_function, unicode_literals

import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from consolidatedscreeninglist_consts import *
import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class ConsolidatedScreeningListConnector(BaseConnector):

    def __init__(self):

        super(ConsolidatedScreeningListConnector, self).__init__()

        self._state = None
        self._auth_token = None
        self._headers = None

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Status code: {}. Empty response and no information in the header".format(response.status_code)
            ), None
        )

    def _process_html_response(self, response, action_result):
        status_code = response.status_code
        if 200 <= status_code < 399:
            return RetVal(phantom.APP_SUCCESS, None)

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
        try:
            resp_json = r.json()
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. {0}".format(err_msg)
                ), None
            )

        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        msg = None
        if resp_json.get("fault") and isinstance(resp_json.get("fault"), dict):
            msg = resp_json.get("fault").get("description")

        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            msg if msg else r.text.replace('{', '{{').replace('}', '}}')
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

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        url = "{}{}".format(BASE_URL, endpoint)

        try:
            r = request_func(
                url,
                verify=False,
                **kwargs
            )
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. {0}".format(err_msg)
                ), resp_json
            )

        return self._process_response(r, action_result)

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
            if error_code in ERR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
        except:
            self.debug_print(PARSE_ERR_MSG)
            error_text = PARSE_ERR_MSG

        return error_text

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Testing the reachability of {}. This action doesn't perform any validation for the asset configuration parameter".format(BASE_URL))
        self.save_progress("Connecting to endpoint")
        ret_val, _ = self._make_rest_call('', action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _validate_integer(self, action_result, parameter, key):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, INVALID_INTEGER_ERR_MSG.format(key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, INVALID_INTEGER_ERR_MSG.format(key)), None

            if parameter <= 0:
                return action_result.set_status(phantom.APP_ERROR, INVALID_NON_ZERO_NON_NEGATIVE_INTEGER_ERR_MSG.format(key)), None

        return phantom.APP_SUCCESS, parameter

    def _paginator(self, action_result, name, country="", fuzzy_name=False, limit=None):
        # This method is used to paginate through the responses using the lookup user endpoint based on the provided request parameters

        params = {"name": name, "countries": country, "fuzzy_name": fuzzy_name, "size": 100}
        offset = 0
        response_dict = {
            "results": [],
            "search_performed_at": None,
            "sources_used": None,
            "total": 0
        }
        while True:
            if offset:
                params.update({"offset": offset})

            ret_val, response = self._make_rest_call(LOOKUP_ENDPOINT, action_result, params=params, headers=self._headers)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), response_dict

            if response.get("sources_used"):
                response_dict["sources_used"] = response["sources_used"]

            if response.get("results"):
                response_dict["results"].extend(response["results"])

            if response.get("search_performed_at"):
                response_dict["search_performed_at"] = response["search_performed_at"]

            if response.get("offset"):
                offset = response["offset"]

            if response.get("total") is not None:
                if response["total"] == 0:
                    return phantom.APP_SUCCESS, response_dict

                response_dict["total"] = response["total"]

                if limit and len(response_dict["results"]) >= limit:
                    response_dict["results"] = response_dict["results"][:limit]
                    return phantom.APP_SUCCESS, response_dict

                offset += 100
                if offset >= response_dict["total"]:
                    return phantom.APP_SUCCESS, response_dict
            else:
                return action_result.set_status(phantom.APP_ERROR, "Received unexpected response from the server"), response_dict

    def _handle_lookup_user(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        name = param['name']
        limit = param.get('limit')
        # Validate 'limit' action parameter
        ret_val, limit = self._validate_integer(action_result, limit, LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        country = param.get('country', '')
        fuzzy_name = param.get('fuzzy_name', False)

        try:
            ret_val, response = self._paginator(action_result, name, country, fuzzy_name, limit)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            action_result.add_data(response)
            summary = action_result.update_summary({})

            if response['total'] == 0:
                summary['match'] = False
            else:
                summary['match'] = True

            summary['total_fetched_results'] = len(response["results"])
        except:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing response from the server")

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        action_id = self.get_action_identifier()

        self.debug_print("action_id: {}".format(self.get_action_identifier()))

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'lookup_user':
            ret_val = self._handle_lookup_user(param)

        return ret_val

    def initialize(self):
        self._state = self.load_state()
        config = self.get_config()
        self._auth_token = config["auth_token"]
        self._headers = {"Authorization": "Bearer {}".format(self._auth_token), "Accept": "application/json"}

        return phantom.APP_SUCCESS

    def finalize(self):
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

        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = BaseConnector._get_phantom_base_url() + '/login'

            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)

        connector = ConsolidatedScreeningListConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
