# File: warc_connector.py
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

# Usage of the consts file is recommended
from warc_consts import *
import requests
import json
import time
from warcio.warcwriter import WARCWriter
from warcio.statusandheaders import StatusAndHeaders
from urllib.parse import urlparse


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class WarcConnector(BaseConnector):
    def __init__(self):

        # Call the BaseConnectors init first
        super(WarcConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

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

        self.save_progress("Connecting to endpoint")

        url = "https://google.com"
        out_file = "{}test.warc.gz".format(PHANTOM_VAULT_DIR)
        try:
            self._fetch_warc(action_result, url, out_file)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.save_progress("Connectivity Test Failed")
            return action_result.set_status(phantom.APP_ERROR, err)

        self.save_progress(out_file)
        self.save_progress("Connectivity Test Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _fetch_warc(self, action_result, url, out_path):
        with open(out_path, "wb") as output:
            writer = WARCWriter(output, gzip=True)

            resp = requests.get(
                url, headers={"Accept-Encoding": "identity"}, stream=True
            )

            # get raw headers from urllib3
            headers_list = resp.raw.headers.items()

            http_headers = StatusAndHeaders("200 OK", headers_list, protocol="HTTP/1.0")

            record = writer.create_warc_record(
                url, "response", payload=resp.raw, http_headers=http_headers
            )

            writer.write_record(record)

        return out_path

    def _handle_get_url(self, param):

        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        url = param["url"]
        parsed_url = urlparse(url)

        curr_time = int(time.time())
        file_path = "{}{}_{}.warc.gz".format(PHANTOM_VAULT_DIR, parsed_url.netloc, curr_time)
        try:
            file_path = self._fetch_warc(action_result, url, file_path)

            vault_ret = Vault.add_attachment(
                file_path, self.get_container_id()
            )
            if vault_ret.get("succeeded"):
                action_result.add_data(vault_ret)

        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, err)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id: {}".format(self.get_action_identifier()))

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)

        elif action_id == "get_url":
            ret_val = self._handle_get_url(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()
        self._base_url = config.get("base_url")

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

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = WarcConnector._get_phantom_base_url() + "/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = WarcConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()
