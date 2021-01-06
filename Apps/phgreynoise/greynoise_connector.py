#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom Greynoise App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# import math
# from datetime import datetime
# from datetime import timedelta

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# from greynoisedev_consts import *
import requests
# from dateutil.parser import parse
import json
import traceback
from requests.utils import requote_uri
from six.moves.urllib.parse import urljoin as _urljoin


def urljoin(base, url):
    return _urljoin("%s/" % base.rstrip("/"), url.lstrip("/"))


class GreyNoiseConnector(BaseConnector):
    _session = None
    _app_version = None

    def validate_parameters(self, param):
        # Disable BaseConnector's validate functionality, since this App supports unicode domains and the
        # validation routines don't
        return phantom.APP_SUCCESS

    def get_session(self):
        if self._session is None:
            config = self.get_config()
            self._session = requests.Session()
            self._session.params.update({
                "api-key": config["api_key"]
            })
        return self._session

    def get_app_version(self):
        if self._app_version is None:
            app_json = self.get_app_json()
            self._app_version = app_json["app_version"]

        return self._app_version

    def _make_rest_call(self, action_result, method, *args, error_on_404=True, **kwargs):
        session = self.get_session()

        response_json = None
        status_code = None
        try:
            r = session.request(method, *args, **kwargs)
            if r.status_code != 404 or error_on_404:
                r.raise_for_status()
            status_code = r.status_code
        except requests.exceptions.HTTPError as e:
            ret_val = action_result.set_status(phantom.APP_ERROR,
                                               "HTTP error making REST call: %s" % e.response.text)
        except Exception:
            ret_val = action_result.set_status(phantom.APP_ERROR,
                                               "General error making REST call: %s" % traceback.format_exc())
        else:
            ret_val = action_result.set_status(phantom.APP_SUCCESS)
            response_json = r.json()

        return (ret_val, response_json, status_code)

    def _check_apikey(self, action_result):
        self.save_progress("Testing API key")
        config = self.get_config()
        app_version = self.get_app_version()
        ret_val, response_json, status_code = self._make_rest_call(
            action_result,
            "get",
            "https://api.greynoise.io/v2/meta/ping",
            headers={"Accept": "application/json", "key": config["api_key"],
                     "User-Agent": "greynoise-phantom-integration-v" + str(app_version)}
        )
        if phantom.is_fail(ret_val):
            self.save_progress("API key check Failed")
            return ret_val

        if response_json is None:
            self.save_progress("No response from API")
            response_json = json.dumps(response_json)
            return action_result.set_status(phantom.APP_ERROR, "No response from API: %s" % response_json)
        elif response_json["message"] == "pong":
            return action_result.set_status(phantom.APP_SUCCESS, "Validated API key")
        else:
            self.save_progress("Invalid response from API")
            response_json = json.dumps(response_json)
            return action_result.set_status(phantom.APP_ERROR, "Invalid response from API: %s" % response_json)

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
        config = self.get_config()
        app_version = self.get_app_version()
        if phantom.is_fail(ret_val):
            return ret_val

        ret_val, response_json, status_code = self._make_rest_call(
            action_result,
            "get",
            "https://api.greynoise.io/v2/noise/quick/%s" % param["ip"],
            headers={"Accept": "application/json", "key": config["api_key"],
                     "User-Agent": "greynoise-phantom-integration-v" + str(app_version)}
        )
        if phantom.is_fail(ret_val):
            return ret_val

        result_data = {}
        action_result.add_data(result_data)

        result_data.update(response_json)

        result_data["visualization"] = "https://viz.greynoise.io/ip/" + str(result_data["ip"])

        if result_data["code"] == "0x00":
            result_data["code_meaning"] = "The IP has never been observed scanning the Internet"
        elif result_data["code"] == "0x01":
            result_data["code_meaning"] = "The IP has been observed by the GreyNoise sensor network"
        elif result_data["code"] == "0x02":
            result_data["code_meaning"] = "The IP has been observed scanning the GreyNoise sensor network, " \
                                          "but has not completed a full connection, meaning this can be spoofed"
        elif result_data["code"] == "0x03":
            result_data["code_meaning"] = "The IP is adjacent to another host that has been directly observed by the" \
                                          " GreyNoise sensor network"
        elif result_data["code"] == "0x04":
            result_data["code_meaning"] = "Reserved"
        elif result_data["code"] == "0x05":
            result_data["code_meaning"] = "This IP is commonly spoofed in Internet-scan activity"
        elif result_data["code"] == "0x06":
            result_data["code_meaning"] = "This IP has been observed as noise, " \
                                          "but this host belongs to a cloud provider where IPs can be cycled frequently"
        elif result_data["code"] == "0x07":
            result_data["code_meaning"] = "This IP is invalid"
        elif result_data["code"] == "0x08":
            result_data["code_meaning"] = "This IP was classified as noise, " \
                                          "but has not been observed engaging in Internet-wide scans or attacks " \
                                          "in over 60 days"
        else:
            result_data["code_meaning"] = "This code is unmapped"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _ip_reputation(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = self._check_apikey(action_result)
        config = self.get_config()
        app_version = self.get_app_version()
        if phantom.is_fail(ret_val):
            return ret_val

        ret_val, response_json, status_code = self._make_rest_call(
            action_result,
            "get",
            "https://api.greynoise.io/v2/noise/context/%s" % param["ip"],
            headers={"Accept": "application/json", "key": config["api_key"],
                     "User-Agent": "greynoise-phantom-integration-v" + str(app_version)}
        )
        if phantom.is_fail(ret_val):
            return ret_val

        result_data = {}
        action_result.add_data(result_data)

        result_data.update(response_json)
        result_data["visualization"] = "https://viz.greynoise.io/ip/" + str(result_data["ip"])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _gnql_query(self, param, is_poll=False):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = self._check_apikey(action_result)
        config = self.get_config()
        app_version = self.get_app_version()
        if phantom.is_fail(ret_val):
            return ret_val

        first_flag = True
        remaining_results_flag = True
        scroll_token = ""
        full_response = {}

        while remaining_results_flag:
            if first_flag:
                ret_val, response_json, status_code = self._make_rest_call(
                    action_result,
                    "get",
                    "https://api.greynoise.io/v2/experimental/gnql",
                    headers={"Accept": "application/json", "key": config["api_key"],
                             "User-Agent": "greynoise-phantom-integration-v" + str(app_version)},
                    params=(('query', param["query"]),
                            ('size', param["size"]))
                )
                full_response.update(response_json)

            if "scroll" in full_response:
                scroll_token = full_response["scroll"]
            if "complete" in full_response or len(full_response["data"]) >= param["size"]:
                remaining_results_flag = False
            elif "message" in full_response:
                if full_response["message"] == "no results":
                    remaining_results_flag = False

            first_flag = False

            if remaining_results_flag:
                ret_val, response_json, status_code = self._make_rest_call(
                    action_result,
                    "get",
                    "https://api.greynoise.io/v2/experimental/gnql",
                    headers={"Accept": "application/json", "key": config["api_key"],
                             "User-Agent": "greynoise-phantom-integration-v" + str(app_version)},
                    params=(('query', param["query"]),
                            ('size', param["size"]),
                            ('scroll', scroll_token))
                )
                full_response["complete"] = response_json["complete"]
                if "scroll" in response_json:
                    full_response["scroll"] = response_json["scroll"]
                for item in response_json["data"]:
                    full_response["data"].append(item)

            if "scroll" in full_response:
                scroll_token = full_response["scroll"]
            if "complete" in full_response or len(full_response["data"]) >= param["size"]:
                remaining_results_flag = False
            elif "message" in full_response:
                if full_response["message"] == "no results":
                    remaining_results_flag = False
            else:
                remaining_results_flag = True

        if phantom.is_fail(ret_val):
            return ret_val

        result_data = {}
        action_result.add_data(result_data)

        for entry in full_response["data"]:
            entry["visualization"] = "https://viz.greynoise.io/ip/" + str(entry["ip"])

        result_data.update(full_response)
        if is_poll:
            return ret_val, result_data
        else:
            return action_result.set_status(phantom.APP_SUCCESS)

    def _lookup_ips(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = self._check_apikey(action_result)
        config = self.get_config()
        app_version = self.get_app_version()
        ips_string = requote_uri(param["ips"])
        if phantom.is_fail(ret_val):
            return ret_val

        ret_val, response_json, status_code = self._make_rest_call(
            action_result,
            "get",
            "https://api.greynoise.io/v2/noise/multi/quick?ips=%s" % ips_string,
            headers={"Accept": "application/json", "key": config["api_key"],
                     "User-Agent": "greynoise-phantom-integration-v" + str(app_version)}
        )
        if phantom.is_fail(ret_val):
            return ret_val

        result_data = []
        action_result.add_data(result_data)

        try:
            for result in response_json:
                if result["code"] == "0x00":
                    result["code_meaning"] = "The IP has never been observed scanning the Internet"
                elif result["code"] == "0x01":
                    result["code_meaning"] = "The IP has been observed by the GreyNoise sensor network"
                elif result["code"] == "0x02":
                    result["code_meaning"] = "The IP has been observed scanning the GreyNoise sensor network, " \
                                             "but has not completed a full connection, meaning this can be spoofed"
                elif result["code"] == "0x03":
                    result["code_meaning"] = "The IP is adjacent to another host that has been directly observed by the" \
                                             " GreyNoise sensor network"
                elif result["code"] == "0x04":
                    result["code_meaning"] = "Reserved"
                elif result["code"] == "0x05":
                    result["code_meaning"] = "This IP is commonly spoofed in Internet-scan activity"
                elif result["code"] == "0x06":
                    result["code_meaning"] = "This IP has been observed as noise, " \
                                             "but this host belongs to a cloud provider where IPs can be cycled frequently"
                elif result["code"] == "0x07":
                    result["code_meaning"] = "This IP is invalid"
                elif result["code"] == "0x08":
                    result["code_meaning"] = "This IP was classified as noise, " \
                                             "but has not been observed engaging in Internet-wide scans or attacks " \
                                             "in over 60 days"
                else:
                    result["code_meaning"] = "This code is unmapped"
                result["visualization"] = "https://viz.greynoise.io/ip/" + str(result["ip"])
                result_data.append(result)
            return action_result.set_status(phantom.APP_SUCCESS)
        except Exception as err:
            message = "Error processing results: %s" % str(err)
            return action_result.set_status(phantom.APP_ERROR, message)

    def _process_query(self, data):
        # spawn container for every item returned
        ret_val = ""
        if data["count"] > 0:
            for entry in data["data"]:
                ip = entry["ip"]
                self.save_progress("Processing IP address {}".format(ip))
                container = {
                    "custom_fields": {},
                    "data": {},
                    "name": "",
                    "description": "Container added by GreyNoise",
                    "label": self.get_config().get("ingest", {}).get("container_label"),
                    "sensitivity": "amber",
                    "source_data_identifier": "",
                    "tags": entry["tags"],
                }

                if entry["classification"] == "malicious":
                    container["severity"] = "high"
                else:
                    container["severity"] = "low"

                artifact_cef = {
                    'ip': entry['ip'],
                    'classification': entry['classification'],
                    'first_seen': entry['first_seen'],
                    'last_seen': entry['last_seen'],
                    'actor': entry['actor'],
                    'organization': entry['metadata']['organization'],
                    'asn': entry['metadata']['asn']
                }
                if entry['metadata']['country']:
                    artifact_cef['country'] = entry['metadata']['country']
                if entry['metadata']['city']:
                    artifact_cef['city'] = entry['metadata']['city']

                container["artifacts"] = [{
                    "cef": artifact_cef,
                    "description": "Artifact added by GreyNoise",
                    "label": container["label"],
                    "name": "GreyNoise Query Language Entry",
                    "source_data_identifier": container["source_data_identifier"],
                    "severity": container["severity"]
                }]

                container["name"] = "GreyNoise Query Language Entry"

                ret_val, _, container_id = self.save_container(container)
                self.save_progress("Created %s" % container_id)

            return ret_val
        else:
            self.save_progress("No results matching your GNQL query were found.")
            ret_val = phantom.APP_SUCCESS
            return ret_val

    def _on_poll(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        if self.is_poll_now():
            self.save_progress('Due to the nature of the API, the '
                               'artifact limits imposed by POLL NOW are '
                               'ignored. As a result POLL NOW will simply '
                               'create a container for each artifact.')

        config = self.get_config()
        param["query"] = config["on_poll_query"]
        if self.is_poll_now():
            param["size"] = param.get(phantom.APP_JSON_CONTAINER_COUNT)
        else:
            param["size"] = config["on_poll_size"]

        if param["query"] == "Please refer to the readme":
            self.save_progress("Default on poll query unchanged, please enter a valid GNQL query")
            return action_result.set_status(phantom.APP_ERROR, "Default on poll query unchanged")

        ret_val, data = self._gnql_query(param, is_poll=True)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val = self._process_query(data)

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, ret_val)
        else:
            return self.set_status(phantom.APP_SUCCESS)

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

        return ret_val
