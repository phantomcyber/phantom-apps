# File: ctix_connector.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)


# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Imports local to this App
import simplejson as json
import base64
import time
import hashlib
import hmac
import requests
import urllib.parse
from ctix_consts import *


class CTIXConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(CTIXConnector, self).__init__()

    def initialize(self):
        config = self.get_config()

        # get authentication variables from Phantom Asset Config
        self._access_id = config["access_id"]
        self._secret_key = config["secret_key"]
        self._baseurl = config["baseurl"].rstrip("/")
        self._verify = config.get("verify_server_cert", True)
        self._expires = int(time.time() + 20)  # expires in 20 seconds

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
                    error_code = CYWARE_ERROR_CODE_MSG
                    error_msg = e.args[0]
            else:
                error_code = CYWARE_ERROR_CODE_MSG
                error_msg = CYWARE_ERROR_MSG_UNAVAILABLE
        except:
            error_code = CYWARE_ERROR_CODE_MSG
            error_msg = CYWARE_ERROR_MSG_UNAVAILABLE

        try:
            if error_code in CYWARE_ERROR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(
                    error_code, error_msg)
        except:
            self.debug_print(CYWARE_PARSE_ERROR_MSG)
            error_text = CYWARE_PARSE_ERROR_MSG

        return error_text

    def _generate_signature(self, access_id, secret_key, expires):
        to_sign = '{}\n{}'.format(access_id, expires)
        sig = base64.b64encode(
            hmac.new(
                secret_key.encode('utf-8'),
                to_sign.encode('utf-8'),
                hashlib.sha1).digest()).decode("utf-8")
        sig_enc = urllib.parse.quote_plus(sig)
        return sig_enc

    def _make_request(self, method, target_url, verify, action_result):

        if method == "GET":
            try:
                r = requests.get(target_url, verify=verify)
                try:
                    rstatus = r.status_code
                    response_json = r.json()
                    return rstatus, response_json
                except Exception as e:
                    err_msg = self._get_error_message_from_exception(e)
                    return action_result.set_status(phantom.APP_ERROR, "Parsing JSON response failed. {}".format(err_msg)), None
            except requests.exceptions.ConnectionError:
                err_msg = "Error connecting to server. Connection refused from the server"
                return action_result.set_status(phantom.APP_ERROR, err_msg), None
            except Exception as e:
                err_msg = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, "GET request failed. {}".format(err_msg)), None
        else:
            return action_result.set_status(phantom.APP_ERROR, "Unsupported REST method"), None

    def _test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Checking connectivity with Cyware CTIX Platform")

        # REST endpoint for retrieving all Threat Intel sources from CTIX
        endpoint = "/source/?Expires={}&AccessID={}&Signature={}&page_size=1".format(
            self._expires, self._access_id, self._generate_signature(self._access_id, self._secret_key, self._expires))

        # Attempt the GET request to CTIX instance and check for successful connection
        try:
            status_code, _ = self._make_request("GET", "{}{}".format(self._baseurl, endpoint), self._verify, action_result)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            self.save_progress(CYWARE_ERR_CONNECTIVITY_TEST)
            return action_result.set_status(phantom.APP_ERROR, CYWARE_GET_REQ_FAILED.format(err_msg))

        if phantom.is_fail(status_code):
            self.save_progress(CYWARE_ERR_CONNECTIVITY_TEST)
            return action_result.get_status()

        if status_code == 200:
            self.save_progress(CYWARE_SUCC_CONNECTIVITY_TEST)
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            return action_result.set_status(phantom.APP_ERROR, "Test Connectivity Failed with status code: {}".format(status_code))

    def _handle_lookup_domain(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # check for required input param
        domain = param["domain"]

        # build full REST endpoint with Auth signature
        # make GET request to CTIX OpenAPI
        try:
            endpoint = "/search/?Expires={}&AccessID={}&Signature={}&domain={}".format(
                self._expires, self._access_id, self._generate_signature(self._access_id, self._secret_key, self._expires), domain)
            status_code, response = self._make_request("GET", "{}{}".format(self._baseurl, endpoint), self._verify, action_result)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            self.save_progress(CYWARE_GET_REQ_FAILED.format(err_msg))
            return action_result.set_status(phantom.APP_ERROR, "Domain lookup failed. {}".format(err_msg))

        if phantom.is_fail(status_code):
            return action_result.get_status()

        # check response status_code
        if status_code == 200:
            try:
                if isinstance(response, list):
                    response = response[0]
                if not isinstance(response, dict):
                    return action_result.set_status(phantom.APP_ERROR, CYWARE_RESP_FROM_SERVER_NOT_JSON)
                # commit action_result
                action_result.set_summary({"message": response['message']})
                action_result.add_data(response)
                self.save_progress("Domain Lookup Successful")
                return action_result.set_status(phantom.APP_SUCCESS, "Domain Lookup Successful")
            except Exception as e:
                err_msg = self._get_error_message_from_exception(e)
                self.save_progress(CYWARE_ADDING_RESP_DATA_TO_ACTION_RESULT_FAILED.format(err_msg))
                return action_result.set_status(phantom.APP_ERROR, CYWARE_ADDING_RESP_DATA_TO_ACTION_RESULT_FAILED.format(err_msg))
        else:
            self.save_progress(CYWARE_GET_REQ_FAILED_WITH_NON_200_STATUS.format(status_code))
            return action_result.set_status(phantom.APP_ERROR, CYWARE_GET_REQ_FAILED_WITH_NON_200_STATUS.format(status_code))

    def _handle_lookup_hash(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # check for required input param
        hashval = param["hash"]

        # build full REST endpoint with Auth signature
        # make GET request to CTIX OpenAPI
        try:
            endpoint = "/search/?Expires={}&AccessID={}&Signature={}&hash={}".format(
                self._expires, self._access_id, self._generate_signature(self._access_id, self._secret_key, self._expires), hashval)
            status_code, response = self._make_request("GET", "{}{}".format(self._baseurl, endpoint), self._verify, action_result)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            self.save_progress(CYWARE_GET_REQ_FAILED.format(err_msg))
            return action_result.set_status(phantom.APP_ERROR, "Hash Lookup failed. {}".format(err_msg))

        if phantom.is_fail(status_code):
            return action_result.get_status()

        # check response status_code
        if status_code == 200:
            try:
                if isinstance(response, list):
                    response = response[0]
                if not isinstance(response, dict):
                    return action_result.set_status(phantom.APP_ERROR, CYWARE_RESP_FROM_SERVER_NOT_JSON)
                # commit action_result
                action_result.set_summary({"message": response['message']})
                action_result.add_data(response)
                self.save_progress("Hash Lookup Successful")
                return action_result.set_status(phantom.APP_SUCCESS, "Hash Lookup Successful")
            except Exception as e:
                err_msg = self._get_error_message_from_exception(e)
                self.save_progress(CYWARE_ADDING_RESP_DATA_TO_ACTION_RESULT_FAILED.format(err_msg))
                return action_result.set_status(phantom.APP_ERROR, CYWARE_ADDING_RESP_DATA_TO_ACTION_RESULT_FAILED.format(err_msg))
        else:
            self.save_progress(CYWARE_GET_REQ_FAILED_WITH_NON_200_STATUS.format(status_code))
            return action_result.set_status(phantom.APP_ERROR, CYWARE_GET_REQ_FAILED_WITH_NON_200_STATUS.format(status_code))

    def _handle_lookup_ip(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # check for required input param
        ip = param["ip"]

        # build full REST endpoint with Auth signature
        # make GET request to CTIX OpenAPI
        try:
            endpoint = "/search/?Expires={}&AccessID={}&Signature={}&ip={}".format(
                self._expires, self._access_id, self._generate_signature(self._access_id, self._secret_key, self._expires), ip)
            status_code, response = self._make_request("GET", "{}{}".format(self._baseurl, endpoint), self._verify, action_result)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            self.save_progress(CYWARE_GET_REQ_FAILED.format(err_msg))
            return action_result.set_status(phantom.APP_ERROR, "IP Lookup failed. {}".format(err_msg))

        if phantom.is_fail(status_code):
            return action_result.get_status()

        # check response status_code
        if status_code == 200:
            try:
                if isinstance(response, list):
                    response = response[0]
                if not isinstance(response, dict):
                    return action_result.set_status(phantom.APP_ERROR, CYWARE_RESP_FROM_SERVER_NOT_JSON)
                # commit action_result
                action_result.set_summary({"message": response['message']})
                action_result.add_data(response)
                self.save_progress(phantom.APP_SUCCESS, "IP Lookup Successful")
                return action_result.set_status(phantom.APP_SUCCESS, "IP Lookup Successful")
            except Exception as e:
                err_msg = self._get_error_message_from_exception(e)
                self.save_progress(CYWARE_ADDING_RESP_DATA_TO_ACTION_RESULT_FAILED.format(err_msg))
                return action_result.set_status(phantom.APP_ERROR, CYWARE_ADDING_RESP_DATA_TO_ACTION_RESULT_FAILED.format(err_msg))
        else:
            self.save_progress(CYWARE_GET_REQ_FAILED_WITH_NON_200_STATUS.format(status_code))
            return action_result.set_status(phantom.APP_ERROR, CYWARE_GET_REQ_FAILED_WITH_NON_200_STATUS.format(status_code))

    def _handle_lookup_url(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # check for required input param
        url = param["url"]

        # build full REST endpoint with Auth signature
        # make GET request to CTIX OpenAPI
        try:
            endpoint = "/search/?Expires={}&AccessID={}&Signature={}&url={}".format(
                self._expires, self._access_id, self._generate_signature(self._access_id, self._secret_key, self._expires), url)
            status_code, response = self._make_request("GET", "{}{}".format(self._baseurl, endpoint), self._verify, action_result)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            self.save_progress(CYWARE_GET_REQ_FAILED.format(err_msg))
            return action_result.set_status(phantom.APP_ERROR, "URL Lookup failed. {}".format(err_msg))

        if phantom.is_fail(status_code):
            return action_result.get_status()

        # check response status_code
        if status_code == 200:
            try:
                if isinstance(response, list):
                    response = response[0]
                if not isinstance(response, dict):
                    return action_result.set_status(phantom.APP_ERROR, CYWARE_RESP_FROM_SERVER_NOT_JSON)
                # commit action_result
                action_result.set_summary({"message": response['message']})
                action_result.add_data(response)
                self.save_progress(phantom.APP_SUCCESS, "URL Lookup Successful")
                return action_result.set_status(phantom.APP_SUCCESS, "URL Lookup Successful")
            except Exception as e:
                err_msg = self._get_error_message_from_exception(e)
                self.save_progress(CYWARE_ADDING_RESP_DATA_TO_ACTION_RESULT_FAILED.format(err_msg))
                return action_result.set_status(phantom.APP_ERROR, CYWARE_ADDING_RESP_DATA_TO_ACTION_RESULT_FAILED.format(err_msg))
        else:
            self.save_progress(CYWARE_GET_REQ_FAILED_WITH_NON_200_STATUS.format(status_code))
            return action_result.set_status(phantom.APP_ERROR, CYWARE_GET_REQ_FAILED_WITH_NON_200_STATUS.format(status_code))

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        if action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            ret_val = self._test_connectivity(param)
        elif action_id == "lookup_domain":
            ret_val = self._handle_lookup_domain(param)
        elif action_id == "lookup_hash":
            ret_val = self._handle_lookup_hash(param)
        elif action_id == "lookup_ip":
            ret_val = self._handle_lookup_ip(param)
        elif action_id == "lookup_url":
            ret_val = self._handle_lookup_url(param)
        return ret_val


if __name__ == '__main__':

    import sys
    import pudb

    pudb.set_trace()

    if (len(sys.argv) < 2):
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CTIXConnector()
        connector.print_progress_message = True
        ret_val = connector.handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
