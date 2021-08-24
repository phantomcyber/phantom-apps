# File: greynoise_connector.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from greynoise_consts import *
from datetime import datetime
import requests
import json
from requests.utils import requote_uri
from six.moves.urllib.parse import urljoin as _urljoin
import urllib.parse


def urljoin(base, url):
    return _urljoin("%s/" % base.rstrip("/"), url.lstrip("/"))


class GreyNoiseConnector(BaseConnector):
    """Connector for GreyNoise App."""

    def __init__(self):
        """GreyNoise App Constructor."""
        super(GreyNoiseConnector, self).__init__()
        self._session = None
        self._app_version = None
        self._api_key = None

    def _get_error_message_from_exception(self, e):
        """This method is used to get appropriate error messages from the exception.
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
                error_text = "Error Code: {0}. Error Message: {1}".format(
                    error_code, error_msg
                )
        except:
            self.debug_print(PARSE_ERR_MSG)
            error_text = PARSE_ERR_MSG

        return error_text

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return (
                        action_result.set_status(
                            phantom.APP_ERROR, VALID_INTEGER_MSG.format(key=key)
                        ),
                        None,
                    )

                parameter = int(parameter)
            except:
                return (
                    action_result.set_status(
                        phantom.APP_ERROR, VALID_INTEGER_MSG.format(key=key)
                    ),
                    None,
                )

            if parameter < 0:
                return (
                    action_result.set_status(
                        phantom.APP_ERROR, NON_NEGATIVE_INTEGER_MSG.format(key=key)
                    ),
                    None,
                )
            if not allow_zero and parameter == 0:
                return (action_result.set_status(phantom.APP_ERROR, NON_NEG_NON_ZERO_INT_MSG.format(key=key)), None)

        return phantom.APP_SUCCESS, parameter

    def get_session(self):
        if self._session is None:
            self._session = requests.Session()
            self._session.params.update({"api-key": self._api_key})
        return self._session

    def _make_rest_call(
        self, action_result, method, *args, **kwargs
    ):
        error_on_404 = False
        session = self.get_session()

        response_json = None
        status_code = None
        try:
            r = session.request(method, *args, **kwargs)
            if r.status_code != 404 or error_on_404:
                r.raise_for_status()
            status_code = r.status_code
        except requests.exceptions.HTTPError as e:
            err_msg = self._get_error_message_from_exception(e)
            err_msg = urllib.parse.unquote(err_msg)
            if "404" in err_msg:
                try:
                    response_json = r.json()
                    ret_val = phantom.APP_SUCCESS
                except Exception as e:
                    err_msg = self._get_error_message_from_exception(e)
                    ret_val = action_result.set_status(
                        phantom.APP_ERROR,
                        "Unable to parse JSON response. Error: {0}".format(err_msg),
                    )
            else:
                ret_val = action_result.set_status(
                    phantom.APP_ERROR,
                    "HTTP error occurred while making REST call: {0}".format(err_msg),
                )
        except requests.exceptions.ConnectionError:
            err_msg = 'Error connecting to server. Connection refused from server'
            ret_val = action_result.set_status(phantom.APP_ERROR, err_msg)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            ret_val = action_result.set_status(
                phantom.APP_ERROR,
                "General error occurred while making REST call: {0}".format(err_msg),
            )
        else:
            try:
                response_json = r.json()
                ret_val = phantom.APP_SUCCESS
            except Exception as e:
                err_msg = self._get_error_message_from_exception(e)
                ret_val = action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to parse JSON response. Error: {0}".format(err_msg),
                )

        return (ret_val, response_json, status_code)

    def _check_apikey(self, action_result):
        self.save_progress("Testing API key")
        ret_val, response_json, status_code = self._make_rest_call(
            action_result, "get", API_KEY_CHECK_URL, headers=self._headers)

        if phantom.is_fail(ret_val):
            self.save_progress("API key check Failed")
            return ret_val

        license_type = response_json.get("offering")
        expiration = str(response_json.get("expiration"))
        try:
            past = datetime.strptime(expiration, "%Y-%m-%d")
        except Exception as e:
            return action_result.set_status(
                phantom.APP_ERROR, "Error occurred while processing response from server. {}".format(self._get_error_message_from_exception(e))
            )
        present = datetime.now()

        if response_json is None:
            self.save_progress("No response from API")
            return action_result.set_status(phantom.APP_ERROR, "No response from API")
        elif response_json.get("message") == "pong":
            if past < present:
                self.save_progress("Validated API Key. License type: {license_type}, Expiration: {expiration}".format(license_type=license_type, expiration=expiration))
                self.save_progress("Your licence is expired and therefore your API key has community permissions")
                self.debug_print("Validated API Key. License type: {license_type}, Expiration: {expiration}".format(license_type=license_type, expiration=expiration))
                self.debug_print("Your licence is expired and therefore your API key has community permissions")
                return phantom.APP_SUCCESS
            else:
                self.save_progress("Validated API Key. License type: {license_type}, Expiration: {expiration}".format(license_type=license_type, expiration=expiration))
                self.debug_print("Validated API Key. License type: {license_type}, Expiration: {expiration}".format(license_type=license_type, expiration=expiration))
                return phantom.APP_SUCCESS
        else:
            self.save_progress("Invalid response from API")
            try:
                response_json = json.dumps(response_json)
            except:
                return action_result.set_status(
                    phantom.APP_ERROR, "Invalid response from API"
                )
            return action_result.set_status(
                phantom.APP_ERROR, "Invalid response from API: %s" % response_json
            )

    def _test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = self._check_apikey(action_result)
        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return ret_val

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _lookup_ip(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = self._check_apikey(action_result)
        if phantom.is_fail(ret_val):
            return ret_val

        ret_val, response_json, status_code = self._make_rest_call(
            action_result,
            "get",
            LOOKUP_IP_URL.format(ip=param["ip"]),
            headers=self._headers,
        )
        if phantom.is_fail(ret_val):
            return ret_val

        result_data = {}
        action_result.add_data(result_data)

        result_data.update(response_json)

        try:
            result_data["visualization"] = VISUALIZATION_URL.format(
                ip=result_data["ip"]
            )
            if result_data["code"] in CODES:
                result_data["code_meaning"] = CODES[result_data["code"]]
            else:
                result_data["code_meaning"] = "This code is unmapped"
        except KeyError:
            return action_result.set_status(
                phantom.APP_ERROR, "Error occurred while processing API response"
            )

        return action_result.set_status(phantom.APP_SUCCESS, "IP Lookup action successfully completed")

    def _riot_lookup_ip(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = self._check_apikey(action_result)
        if phantom.is_fail(ret_val):
            return ret_val

        ret_val, response_json, status_code = self._make_rest_call(
            action_result,
            "get",
            RIOT_IP_URL.format(ip=param["ip"]),
            headers=self._headers,
        )

        if phantom.is_fail(ret_val):
            return ret_val

        result_data = {}
        action_result.add_data(result_data)

        result_data.update(response_json)

        try:
            result_data["visualization"] = VISUALIZATION_URL.format(
                ip=result_data["ip"]
            )
            if result_data["riot"] is False:
                result_data["riot_unseen"] = True
            if "trust_level" in result_data.keys():
                if str(result_data["trust_level"]) in TRUST_LEVELS:
                    result_data["trust_level"] = TRUST_LEVELS[str(result_data["trust_level"])]
        except KeyError:
            return action_result.set_status(
                phantom.APP_ERROR, "Error occurred while processing API response"
            )

        return action_result.set_status(phantom.APP_SUCCESS, "RIOT Lookup IP action successfully completed")

    def _community_lookup_ip(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = self._check_apikey(action_result)
        if phantom.is_fail(ret_val):
            return ret_val

        ret_val, response_json, status_code = self._make_rest_call(
            action_result,
            "get",
            COMMUNITY_IP_URL.format(ip=param["ip"]),
            headers=self._headers,
        )

        if phantom.is_fail(ret_val):
            return ret_val

        result_data = {}
        action_result.add_data(result_data)

        result_data.update(response_json)

        try:
            result_data["visualization"] = VISUALIZATION_URL.format(
                ip=result_data["ip"]
            )
            if result_data["riot"] is False and result_data['noise'] is False:
                result_data["community_not_found"] = True
        except KeyError:
            return action_result.set_status(
                phantom.APP_ERROR, "Error occurred while processing API response"
            )

        return action_result.set_status(phantom.APP_SUCCESS, "Community Lookup IP action successfully completed")

    def _ip_reputation(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = self._check_apikey(action_result)
        if phantom.is_fail(ret_val):
            return ret_val

        ret_val, response_json, status_code = self._make_rest_call(
            action_result,
            "get",
            IP_REPUTATION_URL.format(ip=param["ip"]),
            headers=self._headers,
        )
        if phantom.is_fail(ret_val):
            return ret_val

        result_data = {}
        action_result.add_data(result_data)

        result_data.update(response_json)
        try:
            result_data["visualization"] = VISUALIZATION_URL.format(
                ip=result_data["ip"]
            )
            if result_data["seen"] is False:
                result_data["unseen_rep"] = True
        except KeyError:
            return action_result.set_status(
                phantom.APP_ERROR, "Error occurred while processing API response"
            )

        return action_result.set_status(phantom.APP_SUCCESS, "IP reputation action successfully completed")

    def _gnql_query(self, param, is_poll=False, action_result=None):
        if not is_poll:
            action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = self._check_apikey(action_result)
        if phantom.is_fail(ret_val):
            if is_poll:
                return ret_val, None
            else:
                return ret_val

        first_flag = True
        remaining_results_flag = True
        scroll_token = ""
        full_response = {}
        size = param["size"]
        # Validate 'size' action parameter
        ret_val, size = self._validate_integer(action_result, size, SIZE_ACTION_PARAM)
        if phantom.is_fail(ret_val):
            if is_poll:
                return action_result.get_status(), None
            else:
                return action_result.get_status()

        while remaining_results_flag:
            if first_flag:
                ret_val, response_json, status_code = self._make_rest_call(
                    action_result,
                    "get",
                    GNQL_QUERY_URL,
                    headers=self._headers,
                    params=(("query", param["query"]), ("size", size)),
                )
                if phantom.is_fail(ret_val):
                    if is_poll:
                        return ret_val, None
                    else:
                        return ret_val
                full_response.update(response_json)

            if "scroll" in full_response:
                scroll_token = full_response["scroll"]
            if "complete" in full_response or len(full_response["data"]) >= size:
                remaining_results_flag = False
            elif "message" in full_response:
                if full_response["message"] == "no results":
                    remaining_results_flag = False

            first_flag = False

            if remaining_results_flag:
                ret_val, response_json, status_code = self._make_rest_call(
                    action_result,
                    "get",
                    GNQL_QUERY_URL,
                    headers=self._headers,
                    params=(
                        ("query", param["query"]),
                        ("size", size),
                        ("scroll", scroll_token),
                    ),
                )
                if phantom.is_fail(ret_val):
                    if is_poll:
                        return ret_val, None
                    else:
                        return ret_val
                full_response["complete"] = response_json.get("complete")
                if "scroll" in response_json:
                    full_response["scroll"] = response_json["scroll"]
                for item in response_json["data"]:
                    full_response["data"].append(item)

            if "scroll" in full_response:
                scroll_token = full_response["scroll"]
            if "complete" in full_response or len(full_response["data"]) >= size:
                remaining_results_flag = False
            elif "message" in full_response:
                if full_response["message"] == "no results":
                    remaining_results_flag = False
            else:
                remaining_results_flag = True

        result_data = {}
        action_result.add_data(result_data)
        try:
            for entry in full_response["data"]:
                entry["visualization"] = VISUALIZATION_URL.format(ip=entry["ip"])
        except KeyError:
            error_msg = "Error occurred while processing API response"
            if is_poll:
                return action_result.set_status(phantom.APP_ERROR, error_msg), None
            else:
                return action_result.set_status(phantom.APP_ERROR, error_msg)

        result_data.update(full_response)

        if is_poll:
            return ret_val, result_data
        else:
            return action_result.set_status(phantom.APP_SUCCESS, "GNQL Query action successfully completed")

    def _lookup_ips(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = self._check_apikey(action_result)
        if phantom.is_fail(ret_val):
            return ret_val

        try:
            ips = [x.strip() for x in param["ips"].split(",")]
            ips = list(filter(None, ips))
            if not ips:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    INVALID_COMMA_SEPARATED_VALUE_ERR_MSG.format(key="ips"),
                )
            ips = ",".join(ips)
            ips_string = requote_uri(ips)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            err_msg = (
                "Error occurred while processing 'ips' action parameter. {0}".format(
                    err
                )
            )
            return action_result.set_status(phantom.APP_ERROR, err_msg)

        ret_val, response_json, status_code = self._make_rest_call(
            action_result,
            "get",
            LOOKUP_IPS_URL.format(ips=ips_string),
            headers=self._headers,
        )
        if phantom.is_fail(ret_val):
            return ret_val

        result_data = []
        action_result.add_data(result_data)
        try:
            for result in response_json:
                if result["code"] in CODES:
                    result["code_meaning"] = CODES[result["code"]]
                else:
                    result["code_meaning"] = "This code is unmapped"

                result["visualization"] = VISUALIZATION_URL.format(ip=result["ip"])
                result_data.append(result)

            return action_result.set_status(phantom.APP_SUCCESS, "Lookup IPs action successfully completed")
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            err_msg = "Error occurred while processing results: {0}".format(err)
            return action_result.set_status(phantom.APP_ERROR, err_msg)

    def _process_query(self, data):
        # spawn container for every item returned
        try:
            if data["count"] > 0:
                for entry in data["data"]:
                    ip = entry["ip"]
                    self.save_progress("Processing IP address {}".format(ip))
                    container = {
                        "custom_fields": {},
                        "data": {},
                        "name": "",
                        "description": "Container added by GreyNoise",
                        "label": self.get_config()
                        .get("ingest", {})
                        .get("container_label"),
                        "sensitivity": "amber",
                        "source_data_identifier": "",
                        "tags": entry["tags"],
                    }
                    if entry["classification"] == "malicious":
                        container["severity"] = "high"
                    else:
                        container["severity"] = "low"
                    artifact_cef = {
                        "ip": entry["ip"],
                        "classification": entry["classification"],
                        "first_seen": entry["first_seen"],
                        "last_seen": entry["last_seen"],
                        "actor": entry["actor"],
                        "organization": entry["metadata"]["organization"],
                        "asn": entry["metadata"]["asn"],
                    }
                    if entry["metadata"]["country"]:
                        artifact_cef["country"] = entry["metadata"]["country"]
                    if entry["metadata"]["city"]:
                        artifact_cef["city"] = entry["metadata"]["city"]
                    container["artifacts"] = [
                        {
                            "cef": artifact_cef,
                            "description": "Artifact added by GreyNoise",
                            "label": container["label"],
                            "name": "GreyNoise Query Language Entry",
                            "source_data_identifier": container[
                                "source_data_identifier"
                            ],
                            "severity": container["severity"],
                        }
                    ]
                    container["name"] = "GreyNoise Query Language Entry"

                    ret_val, container_creation_msg, container_id = self.save_container(
                        container
                    )
                    if phantom.is_fail(ret_val):
                        self.save_progress("Error occurred while saving the container")
                        self.debug_print(container_creation_msg)
                        continue
                    self.save_progress("Created Container ID: {}".format(container_id))
                return phantom.APP_SUCCESS
            else:
                self.save_progress("No results matching your GNQL query were found")
                return phantom.APP_SUCCESS
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            err_msg = "Error occurred while processing query data. {}".format(err)
            self.debug_print(err_msg)
            return phantom.APP_ERROR

    def _on_poll(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if self.is_poll_now():
            self.save_progress(
                "Due to the nature of the API, the "
                "artifact limits imposed by POLL NOW are "
                "ignored. As a result POLL NOW will simply "
                "create a container for each artifact."
            )

        config = self.get_config()
        param["query"] = config.get("on_poll_query")

        if self.is_poll_now():
            param["size"] = param.get(phantom.APP_JSON_CONTAINER_COUNT, 25)
        else:
            on_poll_size = config.get("on_poll_size", 25)
            # Validate 'on_poll_size' config parameter
            ret_val, on_poll_size = self._validate_integer(
                action_result, on_poll_size, ONPOLL_SIZE_CONFIG_PARAM
            )
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            param["size"] = on_poll_size

        if param["query"] == "Please refer to the documentation":
            self.save_progress(
                "Default on poll query unchanged, please enter a valid GNQL query"
            )
            return action_result.set_status(
                phantom.APP_ERROR, "Default on poll query unchanged"
            )

        ret_val, data = self._gnql_query(
            param, is_poll=True, action_result=action_result
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val = self._process_query(data)

        if phantom.is_fail(ret_val):
            return action_result.set_status(
                phantom.APP_ERROR, "Failed to process the query"
            )
        else:
            return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        action = self.get_action_identifier()

        if action == "test_connectivity":
            ret_val = self._test_connectivity(param)
        elif action == "lookup_ip":
            ret_val = self._lookup_ip(param)
        elif action == "ip_reputation":
            ret_val = self._ip_reputation(param)
        elif action == "gnql_query":
            ret_val = self._gnql_query(param)
        elif action == "lookup_ips":
            ret_val = self._lookup_ips(param)
        elif action == "on_poll":
            ret_val = self._on_poll(param)
        elif action == "riot_lookup_ip":
            ret_val = self._riot_lookup_ip(param)
        elif action == "community_lookup_ip":
            ret_val = self._community_lookup_ip(param)

        return ret_val

    def initialize(self):
        """Initialize the Phantom integration."""
        self._state = self.load_state()
        config = self.get_config()

        self._api_key = config["api_key"]
        app_json = self.get_app_json()
        self._app_version = app_json["app_version"]

        self._headers = {
            "Accept": "application/json",
            "key": self._api_key,
            "User-Agent": "greynoise-phantom-integration-v{0}".format(
                self._app_version
            ),
        }

        return phantom.APP_SUCCESS

    def finalize(self):
        """Finalize the Phantom integration."""
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
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

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
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

        connector = GreyNoiseConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
