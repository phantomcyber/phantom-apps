# File: expanse_connector.py
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from expanse_consts import STATUS_CODE_200, EXPANSE_USER_AGENT, \
    JSON_CONTENT_TYPE, IP_LOOKUP_INCLUDE_PARAMS

import base64
import requests
from datetime import datetime, timedelta
import json
from bs4 import BeautifulSoup


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class ExpanseConnector(BaseConnector):

    def __init__(self):

        super(ExpanseConnector, self).__init__()

        self._state = None

        self._base_url = "https://expander.expanse.co"
        self._token = None
        self._jwt = None

    def _process_empty_response(self, response, action_result):
        if response.status_code == STATUS_CODE_200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR,
                "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(
            status_code,
            error_text
        )

        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message),
                      None)

    def _process_json_response(self, response, action_result):
        # Try a json parse
        try:
            resp_json = response.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if STATUS_CODE_200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = \
            "Error from server. Status Code: {0} Data from server: {1}".format(
                response.status_code,
                response.text.replace(u'{', '{{').replace(u'}', '}}')
            )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message),
                      None)

    def _process_response(self, response, action_result):
        # store the r_text in debug data
        # it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code':
                                          response.status_code})
            action_result.add_debug_data({'r_text': response.text})
            action_result.add_debug_data({'r_headers': response.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        elif 'html' in response.headers.get('Content-Type', ''):
            return self._process_html_response(response, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        elif not response.text:
            return self._process_empty_response(response, action_result)

        # everything else is actually an error at this point
        else:
            message = \
                "Can't process response from server. \
                    Status Code: {0} Data from server: {1}".format(
                    response.status_code,
                    response.text.replace('{', '{{').replace('}', '}}')
                )
        return RetVal(action_result.set_status(phantom.APP_ERROR, message),
                      None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):

        config = self.get_config()
        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR,
                                         "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url,
                verify=config.get('verify_server_cert', False),
                **kwargs
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _fetch_jwt(self, config):
        # Returns a new JWT using the included token if a no valid JWT exists
        self._token = config.get("Token")
        if self._jwt is not None or \
            (self._state.get('jwt') is not None
                and self._state.get('jwt_exp') is not None):
            # JWT exists and may be valid
            if self._jwt is not None:
                # should be fresh
                return self._jwt
            if self._state.get('jwt') is not None \
                    and self._state.get('jwt_exp') is not None:
                # check if jwt ts is less than 2 hour, if not, renew
                now_epoch = int(datetime.today().strftime('%s'))
                if now_epoch > self._state.get('jwt_exp'):
                    # jwt is old, clear state and retry
                    self._jwt = None
                    del self._state['jwt']
                    del self._state['jwt_exp']
                    return self._fetch_jwt(config)
                else:
                    self._jwt = self._state.get('jwt')
                    return self._jwt
        elif self._token is not None:
            # JWT does not exist, but we can generate a new one
            try:
                return self._request_new_jwt()
            except requests.RequestException as request_exception:
                self.save_progress(
                    "Auth setup failed, expect downstream failure - {}".format(
                        request_exception)
                    )
        else:
            self.save_progress(
                "No JWT or Refresh token found, expect downstream failure."
            )

    def _request_new_jwt(self):
        headers = {
            "User-Agent": EXPANSE_USER_AGENT,
            "Authorization": "Bearer {}".format(self._token),
            "Content-Type": JSON_CONTENT_TYPE,
        }
        r = requests.get("{}/api/v1/idtoken".format(
            self._base_url),
            headers=headers
        )
        if r.status_code == STATUS_CODE_200:
            jwt = r.json().get("token")
            if jwt is not None:
                self._jwt = jwt
                self._state['jwt'] = jwt
                self._state['jwt_exp'] = self._decode_jwt(jwt)['exp']
                return jwt
            else:
                self.save_progress(
                    "Invalid response returned when refreshing JWT."
                )
        else:
            self.save_progress(
                "Invalid response returned from server when refreshing JWT."
            )

    def _decode_jwt(self, token):
        # Uses based64 to decode a jwt to get expire timestamp
        parts = token.split('.')
        if len(parts) != 3:
            # Invalid JWT
            self.save_progress("Invalid JWT token returned from server")
            return
        # this is to avoid Incorrect padding TypeErrors in the base64 module
        padded_payload = parts[1] + '==='
        try:
            return json.loads(
                base64.b64decode(
                    padded_payload.replace('-', '+').replace('_', '/')
                )
            )
        except TypeError:
            self.save_progress("Invalid JWT token returned from server")

    def _get_headers(self, jwt):
        return {
            "User-Agent": EXPANSE_USER_AGENT,
            "Content-Type": JSON_CONTENT_TYPE,
            "Authorization": "JWT {}".format(jwt)
        }

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        config = self.get_config()
        jwt = self._fetch_jwt(config)

        self.save_progress("Connecting to endpoint")
        ret_val, response = self._make_rest_call(
            '/api/v1/Entity/',
            action_result,
            params=None,
            headers=self._get_headers(jwt)
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_ip(self, param):
        config = self.get_config()
        jwt = self._fetch_jwt(config)

        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param['ip']

        ret_val, response = self._make_rest_call(
            '/api/v2/ip-range',
            action_result,
            params={"include": IP_LOOKUP_INCLUDE_PARAMS,
                    "inet": ip},
            headers=self._get_headers(jwt)
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['data'] = response['data']

        # Improve severity stats
        if len(response['data']) > 0:
            if len(response['data'][0].get('severityCounts', [])) > 0:
                sev_counts = {}
                for cts in response['data'][0].get('severityCounts'):
                    sev_counts[cts['type']] = cts['count']
                summary['data'][0]['severity_counts'] = sev_counts

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_domain(self, param):
        config = self.get_config()
        jwt = self._fetch_jwt(config)

        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param['domain']

        ret_val, response = self._make_rest_call(
            '/api/v2/assets/domains',
            action_result,
            params={"domainSearch": domain},
            headers=self._get_headers(jwt)
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['data'] = response['data']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_certificate(self, param):
        config = self.get_config()
        jwt = self._fetch_jwt(config)

        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        action_result = self.add_action_result(ActionResult(dict(param)))

        common_name = param['common_name']

        ret_val, response = self._make_rest_call(
            '/api/v2/assets/certificates',
            action_result,
            params={"commonNameSearch": common_name},
            headers=self._get_headers(jwt)
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['data'] = response['data']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_behavior(self, param):
        config = self.get_config()
        jwt = self._fetch_jwt(config)

        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param['ip']

        start_date = datetime.strftime(datetime.today() - timedelta(days=30),
                                       "%Y-%m-%d")

        ret_val, response = self._make_rest_call(
            '/api/v1/behavior/risky-flows',
            action_result,
            params={"filter[created-after]": start_date + "T00:00:00.000Z",
                    "filter[internal-ip-range]": ip,
                    "page[limit]": 30},
            headers=self._get_headers(jwt)
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['data'] = response['data']

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'lookup_ip':
            ret_val = self._handle_lookup_ip(param)

        elif action_id == 'lookup_domain':
            ret_val = self._handle_lookup_domain(param)

        elif action_id == 'lookup_certificate':
            ret_val = self._handle_lookup_certificate(param)

        elif action_id == 'lookup_behavior':
            ret_val = self._handle_lookup_behavior(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()
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

    args = argparser.parse_args()
    session_id = None

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ExpanseConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
