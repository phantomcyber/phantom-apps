# File: digicert_connector.py
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault
import phantom.rules as ph_rules

# Usage of the consts file is recommended
# Import local
import digicert_consts as consts

import requests
import json
from bs4 import BeautifulSoup

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from cryptography import x509


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class DigiCertConnector(BaseConnector):
    def __init__(self):
        # Call the BaseConnectors init first
        super(DigiCertConnector, self).__init__()

        self._state = None
        self._base_url = None
        self._api_key = None
        self._org_id = None
        self._request_session = None

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"),
            None
        )

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace("{", "{{").replace("}", "}}")

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to parse JSON response. Error: {0}".format(str(e))
                ),
                None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        # Process each "Content-Type" of response separately

        # Process a json response
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY"s return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        # it"s not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error messages from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = consts.ERR_CODE_MSG
        error_msg = consts.ERR_MSG_UNAVAILABLE

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = consts.ERR_CODE_MSG
                    error_msg = e.args[0]
        except Exception:
            pass

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        resp_json = None
        method = method.upper()
        url = "{0}/{1}".format(self._base_url, endpoint.strip("/"))

        try:
            r = self._request_session.request(method, url, **kwargs)
        except requests.exceptions.InvalidSchema:
            error_message = 'Error connecting to server. No connection adapters were found for {}'.format(url)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except requests.exceptions.InvalidURL:
            error_message = 'Error connecting to server. Invalid URL {}'.format(url)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except requests.exceptions.ConnectionError:
            error_message = 'Error Details: Connection Refused from the Server {}'.format(url)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to endpoint")

        # make rest call
        ret_val, response = self._make_rest_call("/user/me", action_result)

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            self.save_progress("Test Connectivity Failed.")
            self.save_progress(action_result.get_message())
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_request_cert(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id = self.get_container_id()

        # required params
        csr = param["csr"]  # vault_id or filename
        server_platform_id = consts.PLATFORM_MAP[param["server_platform"]]
        order_validity_years = int(param["order_validity"])

        # optional params
        cn = param.get("common_name")
        signature_hash = param.get("signature_hash")

        success, msg, vault_info = ph_rules.vault_info(container_id=container_id)

        if not success:
            return action_result.set_status(phantom.APP_ERROR, msg)

        filename = ""
        for vault_item in vault_info:
            if csr == vault_item["vault_id"] or csr == vault_item["name"]:
                filename = vault_item["path"]
                break
        else:
            # 'else' on a for loop is called if it IS NOT broken (i.e. break is never called)
            # in this case that means we did not find a vault item in the list, so return an error
            return action_result.set_status(
                phantom.APP_ERROR,
                "Could not find the csr in the file vault"
            )

        with open(filename, "r") as fp:
            csr_data = fp.read()

        # try to parse the csr
        try:
            csr_req = x509.load_pem_x509_csr(bytes(csr_data, "utf-8"))
            parsed_signature_hash = csr_req.signature_hash_algorithm.name
            # https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Name.get_attributes_for_oid
            parsed_cn = csr_req.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
            self.save_progress("Parsed csr values: siganture_hash={0} CN={1}".format(parsed_signature_hash, parsed_cn))
        except Exception:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Failed to parse the csr, make sure it is in PEM format"
            )

        payload = {
            "certificate": {
                "common_name": cn or parsed_cn,
                "csr": csr_data,
                "signature_hash": signature_hash or parsed_signature_hash,
                "sever_platform": {
                    "id": server_platform_id,
                },
            },
            "organization": {
                "id": int(self._org_id)
            },
            "order_validity": {
                "years": order_validity_years
            }
        }

        # submit the request
        ret_val, response = self._make_rest_call(
            "/order/certificate/ssl",
            action_result,
            method="post",
            json=payload
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        action_result.update_summary({
            "order_id": response["id"],
            "request_id": response["requests"][0]["id"],
            "request_status": response["requests"][0]["status"],
            "common_name": payload["certificate"]["common_name"],
            "signature_hash": payload["certificate"]["signature_hash"]
        })

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_request_status(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        request_id = param["request_id"]
        status = param["status"]

        processor_comment = param.get("comment", "")

        # make rest call, response should be empty
        ret_val, response = self._make_rest_call(
            "/request/{0}/status".format(request_id),
            action_result,
            method="put",
            json={
                "status": status,
                "processor_comment": processor_comment
            }
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        action_result.add_data(response)

        action_result.update_summary({
            "request_id": request_id,
            "status": status,
            "comment": processor_comment,
        })

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_download_cert(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id = self.get_container_id()

        certificate_id = param.get("certificate_id")
        order_id = param.get("order_id")

        if certificate_id:
            endpoint = "/certificate/{0}/download/platform".format(certificate_id)
        elif order_id:
            endpoint = "/certificate/download/order/{0}".format(order_id)
        else:
            return action_result.set_status(
                phantom.APP_ERROR,
                "No certificate id or order id specified"
            )

        url = "{0}/{1}".format(self._base_url, endpoint.strip("/"))
        response = self._request_session.get(url, stream=True)

        if not response.ok:
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.set_status(phantom.APP_ERROR, response.text)

        filename = response.headers["content-disposition"].split("filename=")[1]
        vault_info = Vault.create_attachment(response.content, container_id, file_name=filename)

        if not vault_info["succeeded"]:
            return action_result.set_status(phantom.APP_ERROR, vault_info["message"])

        action_result.update_summary({
            "vault_id": vault_info["vault_id"],
        })

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_request_info(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # required params
        order_id = param["order_id"]

        # submit the request
        ret_val, response = self._make_rest_call(
            "/order/certificate/{0}".format(order_id),
            action_result,
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        action_result.update_summary({
            "order_id": response["id"],
            "order_status": response["status"],
            "common_name": response["certificate"]["common_name"],
        })

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("In digicert handle action. Action ID: {}".format(action_id))

        self.debug_print("action_id", action_id)

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)

        elif action_id == "request_cert":
            ret_val = self._handle_request_cert(param)

        elif action_id == "update_request_status":
            ret_val = self._handle_update_request_status(param)

        elif action_id == "download_cert":
            ret_val = self._handle_download_cert(param)

        elif action_id == "get_request_info":
            ret_val = self._handle_get_request_info(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._base_url = config["base_url"]
        self._api_key = config["api_key"]
        self._org_id = int(config["org_id"])

        # Initialize the requests session that will be used for rest requests
        self._request_session = requests.Session()
        self._request_session.verify = config.get("verify_server_cert", True)
        self._request_session.headers.update({
            "X-DC-DEVKEY": self._api_key
        })

        # Set proxy vars for the session if they are in the environment
        self._request_session.proxies = {}
        env_vars = config.get('_reserved_environment_variables', {})
        if 'HTTP_PROXY' in env_vars:
            self._request_session.proxies['http'] = env_vars['HTTP_PROXY']['value']
        if 'HTTPS_PROXY' in env_vars:
            self._request_session.proxies['https'] = env_vars['HTTPS_PROXY']['value']

        # Use the retry adapter to retry requests based on certain status codes
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[408, 429, 500, 502, 503, 504]
        )
        retry_adapter = HTTPAdapter(max_retries=retry)
        self._request_session.mount("http://", retry_adapter)
        self._request_session.mount("https://", retry_adapter)

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        if self._request_session:
            self._request_session.close()
        return phantom.APP_SUCCESS


if __name__ == "__main__":

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

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = "https://127.0.0.1/login"

            print("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = DigiCertConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
