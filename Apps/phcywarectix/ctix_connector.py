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

    def _generate_signature(self, access_id, secret_key, expires):
        to_sign = '{}\n{}'.format(access_id, expires)
        sig = base64.b64encode(
            hmac.new(
                secret_key.encode('utf-8'),
                to_sign.encode('utf-8'),
                hashlib.sha1).digest()).decode("utf-8")
        sig_enc = urllib.parse.quote_plus(sig)
        return sig_enc

    def _make_request(self, method, target_url, verify):

        if method == "GET":
            try:
                r = requests.get(target_url, verify=verify)
                try:
                    rstatus = r.status_code
                    response_json = r.json()
                    return rstatus, response_json
                except Exception as e:
                    self.save_progress("Parsing request status code or JSON response failed: {}".format(e))
                    return result.set_status(phantom.APP_ERROR, "Parsing JSON response failed: {}".format(e))
            except Exception as e:
                self.save_progress("GET request failed. Error Exception: {}".format(e))
                return result.set_status(phantom.APP_ERROR, "GET request failed: {}".format(e))
        else:
            self.save_progress("Unsupported REST method. Error Exception: {}".format(e))
            return result.set_status(phantom.APP_ERROR, "Unsupported REST method: Error Exception: {}".format(e))

    def _test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult())

        # get authentication variables from Phantom Asset Config
        config = self.get_config()
        access_id = config.get("access_id")
        secret_key = config.get("secret_key")
        baseurl = config.get("baseurl")
        verify = config.get("verify_server_cert")
        expires = int(time.time() + 20)  # expires in 20 seconds

        # get CTIX REST API base URL
        if not baseurl:
            self.save_progress("baseurl must be provided.. please retry.")
            action_result.set_status(phantom.APP_ERROR, "baseurl must be provided.. please retry.")
            return self.get_status()

        # get Access ID and Secret Key
        if not access_id or not secret_key:
            self.save_progress("Access ID and Secret must both be provided.. please retry.")
            action_result.set_status(phantom.APP_ERROR, "Access ID and Secret must both be provided.. please retry.")
            return self.get_status()

        self.save_progress("Checking connectivity with Cyware CTIX Platform.")
        # REST endpoint for retrieving all Threat Intel sources from CTIX
        endpoint = "/source/?Expires={}&AccessID={}&Signature={}&page_size=1".format(expires, access_id, self._generate_signature(access_id, secret_key, expires))

        # Attempt the GET request to CTIX instance and check for successful connection
        try:
            status_code, response = self._make_request("GET", baseurl + endpoint, verify)
        except Exception as e:
            self.save_progress("GET request failed with this Exception: {}".format(e))
            self.set_status(phantom.APP_ERROR, CYWARE_ERR_SERVER_CONNECTION, e)
            self.append_to_message(CYWARE_ERR_CONNECTIVITY_TEST)
            return self.get_status()

        if status_code == 200:
            self.set_status(phantom.APP_SUCCESS)
            return self.set_status_save_progress(phantom.APP_SUCCESS, CYWARE_SUCC_CONNECTIVITY_TEST)
        else:
            return self.set_status_save_progress(phantom.APP_SUCCESS, "Test Connectivity Failed with this status_code: {}".format(status_code))

    def _handle_lookup_domain(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # get authentication variables from Phantom Asset Config
        config = self.get_config()
        access_id = config.get("access_id")
        secret_key = config.get("secret_key")
        baseurl = config.get("baseurl")
        verify = config.get("verify_server_cert")
        expires = int(time.time() + 20)  # expires in 20 seconds

        # check for required input param
        domain = param["domain"]
        if not domain:
            self.save_progress("domain value must be provided.. please retry.")
            action_result.set_status(phantom.APP_ERROR, "domain must be provided.. please retry.")
            return self.get_status()

        # build full REST endpoint with Auth signature
        # make GET request to CTIX OpenAPI
        try:
            endpoint = "/search/?Expires={}&AccessID={}&Signature={}&domain={}".format(
                expires, access_id, self._generate_signature(access_id, secret_key, expires), domain)
            status_code, response = self._make_request("GET", baseurl + endpoint, verify)
        except Exception as e:
            self.save_progress("GET request failed with this Exception: {}".format(e))
            action_result.set_status(phantom.APP_ERROR, "Domain Lookup failed. Error Exception: {}".format(e))
            return action_result.get_status()

        # check request reponse status_code
        if status_code == 200:
            if type(response) == list:
                response = response[0]
            if type(response) != dict:
                return action_result.set_status(phantom.APP_ERROR, "Response from server was unexpectedly not JSON")
            try:
                # commit action_result
                action_result.set_summary({"message": response['message']})
                action_result.add_data(response)
                action_result.set_status(phantom.APP_SUCCESS, "Domain Lookup Successful.")
                return self.set_status_save_progress(phantom.APP_SUCCESS, "Domain Lookup Successful.")
            except Exception as e:
                self.save_progress("Adding response JSON data to action_results Failed with this Exception: {}".format(e))
                action_result.set_status(phantom.APP_ERROR, "Adding response JSON data to action_results Failed with this Exception: {}".format(e))
                return action_result.get_status()
        else:
            self.save_progress("GET request failed with non 200 status code: {}".format(status_code))
            action_result.set_status(phantom.APP_ERROR, "GET request failed with non 200 status code: {}".format(status_code))
            return action_result.get_status()

    def _handle_lookup_hash(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # get authentication variables from Phantom Asset Config
        config = self.get_config()
        access_id = config.get("access_id")
        secret_key = config.get("secret_key")
        baseurl = config.get("baseurl")
        verify = config.get("verify_server_cert")
        expires = int(time.time() + 20)  # expires in 20 seconds

        # check for required input param
        hashval = param["hash"]
        if not hashval:
            self.save_progress("hash value must be provided.. please retry.")
            action_result.set_status(phantom.APP_ERROR, "hash value must be provided.. please retry.")
            return self.get_status()

        # build full REST endpoint with Auth signature
        # make GET request to CTIX OpenAPI
        try:
            endpoint = "/search/?Expires={}&AccessID={}&Signature={}&hash={}".format(
                expires, access_id, self._generate_signature(access_id, secret_key, expires), hashval)
            status_code, response = self._make_request("GET", baseurl + endpoint, verify)
        except Exception as e:
            self.save_progress("GET request failed with this Exception: {}".format(e))
            action_result.set_status(phantom.APP_ERROR, "Hash Lookup failed. Error Exception: {}".format(e))
            return action_result.get_status()

        # check request reponse status_code
        if status_code == 200:
            if type(response) == list:
                response = response[0]
            if type(response) != dict:
                return action_result.set_status(phantom.APP_ERROR, "Response from server was unexpectedly not JSON")
            try:
                # commit action_result
                action_result.set_summary({"message": response['message']})
                action_result.add_data(response)
                action_result.set_status(phantom.APP_SUCCESS, "Hash Lookup Successful.")
                return self.set_status_save_progress(phantom.APP_SUCCESS, "Hash Lookup Successful.")
            except Exception as e:
                self.save_progress("Adding response JSON data to action_results Failed with this Exception: {}".format(e))
                action_result.set_status(phantom.APP_ERROR, "Adding response JSON data to action_results Failed with this Exception: {}".format(e))
                return action_result.get_status()
        else:
            self.save_progress("GET request failed with non 200 status code: {}".format(status_code))
            action_result.set_status(phantom.APP_ERROR, "GET request failed with non 200 status code: {}".format(status_code))
            return action_result.get_status()

    def _handle_lookup_ip(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # get authentication variables from Phantom Asset Config
        config = self.get_config()
        access_id = config.get("access_id")
        secret_key = config.get("secret_key")
        baseurl = config.get("baseurl")
        verify = config.get("verify_server_cert")
        expires = int(time.time() + 20)  # expires in 20 seconds

        # check for required input param
        ip = param["ip"]
        if not ip:
            self.save_progress("IP value must be provided.. please retry.")
            action_result.set_status(phantom.APP_ERROR, "IP value must be provided.. please retry.")
            return self.get_status()

        # build full REST endpoint with Auth signature
        # make GET request to CTIX OpenAPI
        try:
            endpoint = "/search/?Expires={}&AccessID={}&Signature={}&ip={}".format(
                expires, access_id, self._generate_signature(access_id, secret_key, expires), ip)
            status_code, response = self._make_request("GET", baseurl + endpoint, verify)
        except Exception as e:
            self.save_progress("GET request failed with this Exception: {}".format(e))
            action_result.set_status(phantom.APP_ERROR, "IP Lookup failed. Error Exception: {}".format(e))
            return action_result.get_status()

        # check request reponse status_code
        if status_code == 200:
            if type(response) == list:
                response = response[0]
            if type(response) != dict:
                return action_result.set_status(phantom.APP_ERROR, "Response from server was unexpectedly not JSON")
            try:
                # commit action_result
                action_result.set_summary({"message": response['message']})
                action_result.add_data(response)
                action_result.set_status(phantom.APP_SUCCESS, "IP Lookup Successful.")
                return self.set_status_save_progress(phantom.APP_SUCCESS, "IP Lookup Successful.")
            except Exception as e:
                self.save_progress("Adding response JSON data to action_results Failed with this Exception: {}".format(e))
                action_result.set_status(phantom.APP_ERROR, "Adding response JSON data to action_results Failed with this Exception: {}".format(e))
                return action_result.get_status()
        else:
            self.save_progress("GET request failed with non 200 status code: {}".format(status_code))
            action_result.set_status(phantom.APP_ERROR, "GET request failed with non 200 status code: {}".format(status_code))
            return action_result.get_status()

    def _handle_lookup_url(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # get authentication variables from Phantom Asset Config
        config = self.get_config()
        access_id = config.get("access_id")
        secret_key = config.get("secret_key")
        baseurl = config.get("baseurl")
        verify = config.get("verify_server_cert")
        expires = int(time.time() + 20)  # expires in 20 seconds

        # check for required input param
        url = param["url"]
        if not url:
            self.save_progress("URL value must be provided.. please retry.")
            action_result.set_status(phantom.APP_ERROR, "URL value must be provided.. please retry.")
            return self.get_status()

        # build full REST endpoint with Auth signature
        # make GET request to CTIX OpenAPI
        try:
            endpoint = "/search/?Expires={}&AccessID={}&Signature={}&url={}".format(
                expires, access_id, self._generate_signature(access_id, secret_key, expires), url)
            status_code, response = self._make_request("GET", baseurl + endpoint, verify)
        except Exception as e:
            self.save_progress("GET request failed with this Exception: {}".format(e))
            action_result.set_status(phantom.APP_ERROR, "URL Lookup failed. Error Exception: {}".format(e))
            return action_result.get_status()

        # check request reponse status_code
        if status_code == 200:
            if type(response) == list:
                response = response[0]
            if type(response) != dict:
                return action_result.set_status(phantom.APP_ERROR, "Response from server was unexpectedly not JSON")
            try:
                # commit action_result
                action_result.set_summary({"message": response['message']})
                action_result.add_data(response)
                action_result.set_status(phantom.APP_SUCCESS, "URL Lookup Successful.")
                return self.set_status_save_progress(phantom.APP_SUCCESS, "URL Lookup Successful.")
            except Exception as e:
                self.save_progress("Adding response JSON data to action_results Failed with this Exception: {}".format(e))
                action_result.set_status(phantom.APP_ERROR, "Adding response JSON data to action_results Failed with this Exception: {}".format(e))
                return action_result.get_status()
        else:
            self.save_progress("GET request failed with non 200 status code: {}".format(status_code))
            action_result.set_status(phantom.APP_ERROR, "GET request failed with non 200 status code: {}".format(status_code))
            return action_result.get_status()

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
