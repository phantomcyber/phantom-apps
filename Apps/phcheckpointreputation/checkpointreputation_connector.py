# File: checkpointreputation_connector.py
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import sys

# THIS Connector imports
import checkpointreputation_consts as consts

import requests
from requests.exceptions import HTTPError, Timeout
import json


class CheckpointReputationConnector(BaseConnector):

    def __init__(self):
        super(CheckpointReputationConnector, self).__init__()

    def initialize(self):
        state = self.load_state()
        config = self.get_config()

        self._api_key = config[consts.CONFIG_API_KEY]
        self._token = state.get(consts.STATE_TOKEN, None)

        return phantom.APP_SUCCESS

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
                    error_code = consts.ERROR_CODE_MSG
                    error_msg = e.args[0]
            else:
                error_code = consts.ERROR_CODE_MSG
                error_msg = consts.ERROR_MSG_UNAVAILABLE
        except:
            error_code = consts.ERROR_CODE_MSG
            error_msg = consts.ERROR_MSG_UNAVAILABLE

        try:
            if error_code in consts.ERROR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(
                    error_code, error_msg)
        except:
            self.debug_print(consts.PARSE_ERROR_MSG)
            error_text = consts.PARSE_ERROR_MSG

        return error_text

    def finalize(self):
        state = {
            consts.STATE_TOKEN: self._token
        }
        self.save_state(state)

        return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, params):
        """
        Only a wrapper around _get_reputation to test connectivity.
        """
        params[consts.ACTION_PARAM_RESOURCE] = consts.ACTION_PARAM_RESOURCE_TEST

        self.save_progress("Connecting to the Check Point reputation API")

        ret_val = self._get_reputation(params, consts.API_ENDPOINT_URL)

        if phantom.is_fail(ret_val):
            self.save_progress("Login to Check Point reputation API failed")
            self.save_progress("Test Connectivity Failed")
        else:
            self.save_progress("Login to Check Point reputation API is successful")
            self.save_progress("Test Connectivity Passed")

        return ret_val

    def _get_reputation(self, params, endpoint):
        """
        Primary function that handles the action trigger and logging.
        """
        action_result = self.add_action_result(ActionResult(dict(params)))
        rest_handler = self._reputation_rest_call
        rest_kwargs = {
            "endpoint": endpoint,
            "resource": params[consts.ACTION_PARAM_RESOURCE]
        }

        try:
            result = self._token_manager(rest_handler, rest_kwargs)
        except HTTPError as err:
            error = self._get_error_message_from_exception(err)
            return action_result.set_status(phantom.APP_ERROR, f"{consts.ERROR_HTTP}. {error}", response=err.response.text)
        except json.JSONDecodeError as err:
            error = self._get_error_message_from_exception(err)
            return action_result.set_status(phantom.APP_ERROR, f"{consts.ERROR_JSON}. {error}")
        except Timeout as err:
            error = self._get_error_message_from_exception(err)
            return action_result.set_status(phantom.APP_ERROR, f"{consts.ERROR_TIMEOUT}. {error}")
        except BaseException as err:
            error = self._get_error_message_from_exception(err)
            return action_result.set_status(phantom.APP_ERROR, f"{consts.ERROR_OTHER}. {error}")

        for response in result.get(consts.RESPONSE):

            action_result.add_data(response)

            response_status = response.get(consts.RESPONSE_STATUS, {})
            response_status_label = response_status.get(
                consts.RESPONSE_STATUS_LABEL,
                consts.RESPONSE_STATUS_LABEL_ERROR
            )
            response_status_message = response_status.get(
                consts.RESPONSE_STATUS_MESSAGE,
                consts.RESPONSE_STATUS_MESSAGE_DEFAULT
            )

            if response_status_label in consts.RESPONSE_STATUS_LABEL_SUCCESSES:
                result_message = consts.RESPONSE_STATUS_MESSAGE_SUCCESS.format(
                    **response,
                    **response.get(consts.RESPONSE_REPUTATION, {})
                )
                action_result.set_status(phantom.APP_SUCCESS, result_message)
            else:
                action_result.set_status(phantom.APP_ERROR, response_status_message)

        return action_result.get_status()

    def _token_manager(self, rest_function, kwargs):
        """
        Wrapper function that handles API token for an API rest call.
        Checkpoint does not have a simple endpoint to check if a token is valid.
        It relies instead on returning an error 403. Which we catch to recreate a token
        and retry the call.
        """
        if not self._token:
            self._token = self._create_token()

        try:
            result = rest_function(**kwargs)
        except HTTPError as err:
            if err.response.status_code == 403:
                self._token = None
                self._token = self._create_token()
                result = rest_function(**kwargs)
            else:
                raise err

        return result

    def _create_token(self):
        """
        Method that gets a new API token and sets it in self._token.
        Returns a new token.
        Raises HTTPError on fail.
        """
        self._token = None

        full_url = f"{consts.API_BASE_URL}{consts.API_ENDPOINT_AUTH}"

        headers = {
            "accept": "*/*",
            "Client-Key": self._api_key
        }

        response = requests.get(full_url, headers=headers)
        response.raise_for_status()

        return response.text

    def _reputation_rest_call(self, endpoint, resource):
        """
        Function that takes care of calling the API.
        Returns a dictionnary on success.
        Raises an HTTPError on issue.
        Raises json.JSONDecodeError on invalid answer.
        """
        full_url = f"{consts.API_BASE_URL}{endpoint}"
        headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
            "Client-Key": self._api_key,
            "token": self._token
        }
        params = {"resource": resource}
        payload = {"request": [{"resource": resource}]}

        response = requests.post(full_url, params=params, headers=headers, json=payload, timeout=(3.05, 10))
        response.raise_for_status()

        return response.json()

    def handle_action(self, params):

        action = self.get_action_identifier()
        ret_val = phantom.APP_SUCCESS
        if action == consts.ACTION_ID_IP:
            ret_val = self._get_reputation(params, consts.API_ENDPOINT_IP)
        elif action == consts.ACTION_ID_URL:
            ret_val = self._get_reputation(params, consts.API_ENDPOINT_URL)
        elif action == consts.ACTION_ID_FILE:
            ret_val = self._get_reputation(params, consts.API_ENDPOINT_FILE)
        elif action == consts.ACTION_ID_TEST:
            ret_val = self._handle_test_connectivity(params)

        return ret_val


if __name__ == '__main__':
    """ Code that is executed when run in standalone debug mode
    for .e.g:
    python2.7 ./checkpointreputation_connector.py /tmp/checkpointreputation_test_url_reputation.json
        """

    # Imports
    import pudb

    # Breakpoint at runtime
    pudb.set_trace()

    # The first param is the input json file
    with open(sys.argv[1]) as f:
        # Load the input json file
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=' ' * 4))

        # Create the connector class object
        connector = CheckpointReputationConnector()

        # Se the member vars
        connector.print_progress_message = True

        # Call BaseConnector::_handle_action(...) to kickoff action handling.
        ret_val = connector._handle_action(json.dumps(in_json), None)

        # Dump the return value
        print(ret_val)

    exit(0)
