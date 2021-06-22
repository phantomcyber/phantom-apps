# File: cofensetriagev2_connector.py
#
# Copyright (c) 2021 Cofense
#
# This unpublished material is proprietary to Cofense.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Cofense.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault
import phantom.rules as ph_rules
import phantom.utils as ph_utils

from cofensetriagev2_consts import *
import requests
import json
from bs4 import BeautifulSoup
import default_timezones
import dateutil.parser
import tempfile


class RetVal(tuple):
    """Represet a class to create a tuple."""

    def __new__(cls, val1, val2=None):
        """Create a tuple from the provided values."""
        return tuple.__new__(RetVal, (val1, val2))


class CofenseTriageConnector(BaseConnector):
    """Represent a connector module that implements the actions that are provided by the app. CofenseTriageConnector is a class that is derived from the BaseConnector class."""

    def __init__(self):
        """Initialize global variables."""
        # Call the BaseConnectors init first
        super(CofenseTriageConnector, self).__init__()

        self._state = {}
        self._base_url = None
        self._access_token = None
        self._client_id = None
        self._client_secret = None
        self._category_id_to_severity = None
        self._user_info = None
        self._is_poll_now = None
        self._is_on_poll = None
        self._update_state_after = None
        self._dup_data = 0
        self._less_data = False
        self._remaining = None

    def _process_empty_response(self, response, action_result):
        if response.status_code in [200, 204]:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Status Code: {0}. Empty response and no information in the header".format(response.status_code)
            ), None
        )

    def _get_error_message_from_exception(self, e):
        """
        Get appropriate error message from the exception.

        :param e: exception object
        :return: error message
        """
        error_msg = COFENSE_ERROR_MESSAGE
        error_code = COFENSE_ERROR_CODE_MESSAGE
        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = COFENSE_ERROR_CODE_MESSAGE
                    error_msg = e.args[0]
        except:
            pass

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

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
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            msg = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(msg)
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        if "errors" in resp_json and resp_json.get("errors", []):
            message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code,
                resp_json.get("errors")[0].get("detail", r.text.replace('{', '{{').replace('}', '}}'))
            )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # preempt adding binary downloads to debug data
        if int(r.status_code) == 200 and (r.headers.get('Content-Transfer-Encoding') == "binary" or r.headers.get('Content-Type') == "application/octet-stream"):
            return RetVal(phantom.APP_SUCCESS, r.content)

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call_oauth2(self, url, action_result, headers=None, params=None, data=None, json=None, method="get"):
        """
        Make the REST call to the app.

        :param url: URL of the resource
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """
        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        try:
            r = request_func(url, json=json, data=data, headers=headers, params=params, verify=self._verify)
            self._r = r
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error connecting to server. Details: {0}".format(self._get_error_message_from_exception(e))), resp_json

        return self._process_response(r, action_result)

    def _make_rest_call_helper_oauth2(self, action_result, endpoint, headers=None, params=None, data=None, json=None, method="get"):
        """
        Help setting a REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """
        url = "{0}{1}".format(self._base_url, endpoint)
        if headers is None:
            headers = {}

        token = self._state.get(COFENSE_OAUTH_TOKEN_STRING, {})
        if not token.get(COFENSE_OAUTH_ACCESS_TOKEN_STRING):
            ret_val = self._generate_new_access_token(action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

        headers.update({
            'Authorization': COFENSE_AUTHORIZATION_HEADER.format(self._access_token)
        })

        ret_val, resp_json = self._make_rest_call_oauth2(url, action_result, headers, params, data, json, method)

        # If token is expired, generate a new token
        msg = action_result.get_message()

        if msg and 'Status Code: 401' in msg:
            ret_val = self._generate_new_access_token(action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            headers.update({'Authorization': COFENSE_AUTHORIZATION_HEADER.format(self._access_token)})

            ret_val, resp_json = self._make_rest_call_oauth2(url, action_result, headers, params, data, json, method)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, resp_json

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        """
        Validate an integer.

        :param action_result: object of ActionResult class
        :param parameter: value to validate
        :param key: name of the parameter
        :param allow_zero: whether zero should be allowed or not
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, value
        """
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_INTEGER_ERR_MSG.format(key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_INTEGER_ERR_MSG.format(key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, COFENSE_NEGATIVE_INTEGER_ERR_MSG.format(key)), None

            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, COFENSE_ZERO_INTEGER_ERR_MSG.format(key)), None

        return phantom.APP_SUCCESS, parameter

    def _parse_datetime(self, action_result, datestring, key):
        """
        Parse the datetime.

        :param action_result: object of ActionResult class
        :param datestring: date string to parse
        :param key: name of the parameter
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS
        """
        if not datestring:
            return phantom.APP_SUCCESS

        # Always default into utc if timezone is not specified
        default_time = dateutil.parser.parse("00:00Z")
        tzinfos = default_timezones.timezones()
        try:
            dt = dateutil.parser.parse(datestring.upper(), tzinfos=tzinfos, default=default_time)
            dt.astimezone(dateutil.tz.tzutc())
            return phantom.APP_SUCCESS
        except:
            msg = COFENSE_INVALID_PARAMETER.format(key)
            return action_result.set_status(phantom.APP_ERROR, msg)

    def _get_user_info(self, action_result):
        """
        Fetch the user information.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, API response
        """
        url = "{}{}".format(self._get_phantom_base_url().strip("/"), "/rest/user_info")
        try:
            r = requests.get(url, verify=False)
            response = r.json()
        except:
            return action_result.set_status(phantom.APP_ERROR, "Error: failed to get user_info"), None

        if r.status_code != 200:
            return action_result.set_status(phantom.APP_ERROR, "Error: failed to get user_info"), None

        return phantom.APP_SUCCESS, response

    def _validate_label(self, label, action_result):
        """
        Validate the label.

        :param label: value of the label
        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, label
        """
        label = label.lower()
        if not self._user_info:
            status, self._user_info = self._get_user_info(action_result)
            if phantom.is_fail(status):
                return action_result.get_status(), None

        if 'labels' not in self._user_info:
            return action_result.set_status(phantom.APP_ERROR, COFENSE_DATA_NOT_FOUND.format(COFENSE_LABEL_STRING)), None

        if label not in self._user_info['labels']:
            return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_PARAMETER.format(COFENSE_LABEL_STRING)), None

        return phantom.APP_SUCCESS, label

    def _validate_tenant(self, tenant, action_result):
        """
        Validate the tenant.

        :param label: value of the tenant
        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, tenant ID
        """
        tenant = tenant.lower()
        if not self._user_info:
            status, self._user_info = self._get_user_info(action_result)
            if phantom.is_fail(status):
                return action_result.get_status(), None

        if 'tenants' not in self._user_info:
            return action_result.set_status(phantom.APP_ERROR, COFENSE_DATA_NOT_FOUND.format(COFENSE_TENANT_STRING)), None

        for t in self._user_info['tenants']:
            if tenant == str(t.get('name', "")).lower() or tenant == str(t.get('id', "")):
                return phantom.APP_SUCCESS, t.get('id', "")

        return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_PARAMETER.format(COFENSE_TENANT_STRING)), None

    def _filter_data(self, response, category_id, reporter_id):
        """
        Filter the data based on the parameters.

        :param response: API response
        :param category_id: category ID of the report to filter on
        :param reporter_id: reporter ID of the report to filter on
        :return: filtered data
        """
        data = list()
        for item in response.get("data", []):
            cdata = item.get("relationships", {}).get("category", {}).get("data")
            rdata = item.get("relationships", {}).get("reporter", {}).get("data")
            if category_id and reporter_id:
                if cdata and rdata and cdata.get("id") == str(category_id) and rdata.get("id") == str(reporter_id):
                    data.append(item)
            elif category_id:
                if cdata and cdata.get("id") == str(category_id):
                    data.append(item)
            elif reporter_id and rdata and rdata.get("id") == str(reporter_id):
                data.append(item)
        return data

    def _paginator(self, action_result, endpoint, params=None, max_results=0, category_id=None, reporter_id=None):
        """
        Fetch results from multiple API calls using pagination for given endpoint.

        :param action_result: object of ActionResult class
        :param endpoint: REST endpoint that needs to be appended to the service address
        :param params: request parameters
        :param max_results: maximum number of results to return
        :param category_id: category ID of the report to filter on
        :param reporter_id: reporter ID of the report to filter on
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, results
        """
        if not isinstance(params, dict):
            params = dict()
        data = list()
        params["page[size]"] = 200
        page = 1
        while True:
            params["page[number]"] = page
            status, response = self._make_rest_call_helper_oauth2(action_result, endpoint, params=params)
            if phantom.is_fail(status):
                return action_result.get_status(), data
            if category_id or reporter_id:
                data.extend(self._filter_data(response, category_id, reporter_id))
            else:
                data.extend(response.get("data", []))
            if max_results and len(data) >= max_results:
                return phantom.APP_SUCCESS, data[:max_results]
            if not response.get("links", {}).get("next"):
                break
            page += 1

        self._less_data = True
        return phantom.APP_SUCCESS, data

    def _remap_cef(self, cef, cef_mapping):
        """
        Remap the cef field.

        :param cef: old cef
        :param cef_mapping: mapping between the old and the new cef
        :return: remapped cef
        """
        if not cef:
            return dict()

        if not cef_mapping:
            return cef.copy()

        newcef = dict()
        for key, value in list(cef.items()):
            if isinstance(value, dict):
                value = self._remap_cef(value, cef_mapping)
            newkey = cef_mapping.get(key, key)
            newcef[newkey] = value

        return newcef

    def _create_artifacts(self, is_list, response, cef_mapping, key, parent_type, parent_id):
        """
        Create artifacts.

        :param is_list: indicates whether the response is a list or not
        :param response: API response
        :param cef_mapping: mapping between the old and the new cef
        :param key: the name of subfield
        :param parent_type: parent type of the subfield
        :param parent_id: parent ID of the subfield
        :return: list of artifact objects created from subfields
        """
        artifacts = list()
        if not is_list:
            data = response.get("data")
            if data:
                cef = self._remap_cef(data, cef_mapping)
                artifacts += [{
                    "source_data_identifier": "{} id {} {} id {}".format(parent_type, parent_id, key, data.get("id")),
                    "name": COFENSE_ARTIFACT_NAME.format(key.capitalize()),
                    "cef": cef,
                    "severity": COFENSE_DEFAULT_SEVERITY
                }]
        else:
            if response:
                for item in response:
                    cef = self._remap_cef(item, cef_mapping)
                    item_type = item.get("type")
                    severity = COFENSE_DEFAULT_SEVERITY
                    if item_type == "reports":
                        severity = self._get_severity_from_category(item)
                    elif item_type == "threat_indicators":
                        severity = self._get_severity_from_threat_level(item)
                    artifacts += [{
                        "source_data_identifier": "{} id {} {} id {}".format(parent_type, parent_id, key.strip("s"), item.get("id")),
                        "name": COFENSE_ARTIFACT_NAME.format(key.strip("s").capitalize()),
                        "cef": cef,
                        "severity": severity
                    }]

        return artifacts

    def _fetch_subfields(self, action_result, subfields, cef_mapping, parent_id, parent_type):
        """
        Fetch the subfields.

        :param action_result: object of ActionResult class
        :param subfields: subfields
        :param cef_mapping: mapping between the old and the new cef
        :param parent_id: parent ID of the subfields
        :param parent_type: parent type of the subfields
        :return: list of artifact objects created from subfields
        """
        artifacts = list()

        for key, value in list(subfields.items()):
            if "data" in value:
                if not value.get("data"):
                    continue
                else:
                    endpoint = value.get("links", {}).get("related")
                    endpoint = endpoint[endpoint.index("/api"):]
                    status, response = self._make_rest_call_helper_oauth2(action_result, endpoint)
                    if phantom.is_fail(status):
                        continue
                    artifacts.extend(self._create_artifacts(False, response, cef_mapping, key, parent_type, parent_id))
            else:
                endpoint = value.get("links", {}).get("related")
                endpoint = endpoint[endpoint.index("/api"):]
                status, response = self._paginator(action_result, endpoint)
                if phantom.is_fail(status):
                    continue
                artifacts.extend(self._create_artifacts(True, response, cef_mapping, key, parent_type, parent_id))

        return artifacts

    def _get_severity_from_category(self, report):
        """
        Decide the severity based on the report's category.

        :param report: report
        :return: severity
        """
        category = report.get("relationships", {}).get("category", {}).get("data")
        if category:
            cid = category.get("id")
            if self._category_id_to_severity:
                for key, value in list(self._category_id_to_severity.items()):
                    if cid in value:
                        return key
            for key, value in list(COFENSE_CATEGORY_ID_TO_SEVERITY.items()):
                if cid in value:
                    return key
        return COFENSE_DEFAULT_SEVERITY

    def _get_severity_from_threat_level(self, threat):
        """
        Decide the severity based on the threat indicator's threat level.

        :param threat: threat indicator
        :return: severity
        """
        level = threat.get("attributes", {}).get("threat_level", "").lower()
        for key, value in list(COFENSE_THREAT_LEVEL_TO_SEVERITY.items()):
            if level in value:
                return key
        return COFENSE_DEFAULT_SEVERITY

    def _add_container_data(self, x, data_type, label, tenant):
        """
        Add data to the container.

        :param x: object of data
        :param data_type: the type of data
        :param label: label of the container
        :param tenant: tenant to ingest the container for
        :return: container dictionary
        """
        if data_type == "report":
            container = {
                'label': label,
                'name': x.get("attributes", {}).get("subject"),
                "source_data_identifier": "report id {}".format(x.get("id")),
                'severity': self._get_severity_from_category(x)
            }
        else:
            x_id = x.get("id")
            container = {
                'label': label,
                'name': "Threat Indicator ID {}".format(x_id),
                "source_data_identifier": "threat indicator id {}".format(x_id),
                'severity': self._get_severity_from_threat_level(x)
            }

        if tenant is not None:
            container['tenant_id'] = tenant

        return container

    def _ingest_data(self, action_result, ingest_subfields, data, label, tenant, cef_mapping, data_type, key):
        """
        Ingest data and its subfields into Phantom.

        :param action_result: object of ActionResult class
        :param ingest_subfields: whether or not to ingest the subfields of the report
        :param reports: data to ingest
        :param label: label of the container
        :param tenant: tenant to ingest the container for
        :param cef_mapping: mapping between the old and the new cef
        :param data_type: type of data to ingest
        :param key: key for saving context
        :return: phantom.APP_SUCCESS
        """
        self.save_progress("Ingesting the data")
        self.debug_print("Ingesting the data")
        is_scheduled_poll = self._is_on_poll and not self._is_poll_now
        count = 1
        self._dup_data = 0
        config = self.get_config()

        for x in data:
            artifacts = []
            x_id = x.get("id")
            container = self._add_container_data(x, data_type, label, tenant)

            # Construct artifact
            cef = self._remap_cef(x, cef_mapping)
            artifacts += [{
                "source_data_identifier": "{} id {}".format(data_type, x_id),
                "name": COFENSE_ARTIFACT_NAME.format(data_type.title()),
                "cef": cef,
                "severity": container["severity"]
            }]

            status, message, container_id = self.save_container(container)
            if phantom.is_fail(status):
                self.debug_print("Error occurred while saving the container: ID {}: {}".format(container_id, message))
                continue

            if "Duplicate container found" in message:
                self._dup_data += 1

            if ingest_subfields:
                subfields = x.get("relationships", {})
                subfield_artifacts = self._fetch_subfields(action_result, subfields, cef_mapping, x_id, data_type)
                artifacts += subfield_artifacts

            for artifact in artifacts:
                artifact['container_id'] = container_id
            status, message, _ = self.save_artifacts(artifacts)
            if phantom.is_fail(status):
                self.debug_print("Error occurred while saving the artifact(s): {}".format(message))
                continue

            if count == self._update_state_after and is_scheduled_poll and config["sort"] == "oldest_first":
                self._state[key] = x.get("attributes", {}).get("updated_at")
                self.save_state(self._state)
                self.debug_print("Ingestion time updated")
                count = 0

            count += 1

            self.save_progress("{} id ({}) is ingested in container id ({})".format(data_type, x_id, container_id))
            self.debug_print("{} id ({}) is ingested in container id ({})".format(data_type, x_id, container_id))
            x["container_id"] = container_id

        return phantom.APP_SUCCESS

    def _validate_ingestion_params(self, action_result, param):
        """
        Validate ingestion parameters.

        :param action_result: object of ActionResult class
        :param param: dictionary of params
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, label, tenant, cef_mapping
        """
        cef_mapping = param.get("cef_mapping")
        label = param.get("label")
        tenant = param.get("tenant")
        # Validate 'label'
        if not label:
            msg = COFENSE_EMPTY_PARAMETER.format(COFENSE_LABEL_STRING)
            return action_result.set_status(phantom.APP_ERROR, msg), label, tenant, cef_mapping
        status, label = self._validate_label(label, action_result)
        if phantom.is_fail(status):
            return action_result.get_status(), label, tenant, cef_mapping

        # Validate 'tenant'
        if self._is_on_poll and tenant == "NONE":
            tenant = None
        else:
            if not tenant:
                msg = COFENSE_EMPTY_PARAMETER.format(COFENSE_TENANT_STRING)
                return action_result.set_status(phantom.APP_ERROR, msg), label, tenant, cef_mapping
            status, tenant = self._validate_tenant(tenant, action_result)
            if phantom.is_fail(status):
                return action_result.get_status(), label, tenant, cef_mapping

        # Validate 'cef_mapping' parameter
        if cef_mapping:
            try:
                cef_mapping = json.loads(cef_mapping)
            except:
                msg = COFENSE_INVALID_JSON_PARAMETER.format("'cef_mapping'")
                return action_result.set_status(phantom.APP_ERROR, msg), label, tenant, cef_mapping

        return phantom.APP_SUCCESS, label, tenant, cef_mapping

    def _get_reporter_from_email(self, action_result, email):
        """
        Retrieve reporter ID for the provided email

        :param action_result: object of ActionResult class
        :param email: reporter's email address
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, reporter ID
        """
        reporter_id = None
        reporter_params = {
            "filter[email]": email
        }
        status, response = self._make_rest_call_helper_oauth2(action_result, COFENSE_REPORTERS_ENDPOINT, params=reporter_params)
        if phantom.is_fail(status):
            return action_result.get_status(), reporter_id

        reporters = response.get("data")
        if not reporters:
            return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_REPORTER_EMAIL), reporter_id
        reporter_id = reporters[0].get("id")

        return phantom.APP_SUCCESS, reporter_id

    def _validate_datetime_parameters(self, action_result, start_date, end_date):
        """
        Validate the date parameters.

        :param action_result: object of ActionResult class
        :param start_date: start date
        :param end_date: end date
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS
        """
        # Validate 'start_date' parameter
        status = self._parse_datetime(action_result, start_date, "'start_date'")
        if phantom.is_fail(status):
            return action_result.get_status()

        # Validate 'end_date' parameter
        status = self._parse_datetime(action_result, end_date, "'end_date'")
        if phantom.is_fail(status):
            return action_result.get_status()

        return phantom.APP_SUCCESS

    def _validate_pagination_parameters(self, action_result, max_results):
        """
        Validate the pagination parameters.

        :param action_result: object of ActionResult class
        :param max_results: maximum number of results to return
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, max_results
        """
        # Validate 'max_results' parameter
        ret_val, max_results = self._validate_integer(action_result, max_results, "'max_results'")
        if phantom.is_fail(ret_val):
            return action_result.get_status(), max_results

        return phantom.APP_SUCCESS, max_results

    def _validate_process_reports_parameters(self, param, action_result):
        """
        Validate parameters of process_reports method.

        :param param: dictionary of params
        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, processed_parameters
        """
        processed_params = dict()
        location = param.get("location")
        if location and location.lower() not in COFENSE_REPORT_LOCATIONS:
            return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_PARAMETER.format("'location'")), processed_params

        from_address = param.get("from_address")
        subject = param.get("subject")
        processed_params.update({
            "location": location,
            "from_address": from_address,
            "subject": subject
        })

        match_priority = param.get("match_priority")
        # Validate 'match_priority' parameter
        ret_val, match_priority = self._validate_integer(action_result, match_priority, "'match_priority'", True)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), processed_params
        processed_params["match_priority"] = match_priority

        category_id = param.get("category_id")
        # Validate 'category_id' parameter
        ret_val, category_id = self._validate_integer(action_result, category_id, "'category_id'")
        if phantom.is_fail(ret_val):
            return action_result.get_status(), processed_params
        processed_params["category_id"] = category_id

        start_date = param.get("start_date")
        end_date = param.get("end_date")
        status = self._validate_datetime_parameters(action_result, start_date, end_date)
        if phantom.is_fail(status):
            return action_result.get_status(), processed_params
        processed_params.update({
            "start_date": start_date,
            "end_date": end_date
        })

        sort = param.get("sort", "oldest_first")
        if sort not in COFENSE_SORT_VALUES:
            return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_PARAMETER.format(COFENSE_SORT_STRING)), processed_params

        ingest_report = param.get("ingest_report", False)
        ingest_subfields = param.get("ingest_subfields", False)
        ingest = ingest_report or ingest_subfields
        processed_params.update({
            "sort": sort,
            "ingest_subfields": ingest_subfields,
            "ingest": ingest
        })

        if ingest:
            # Validate ingestion parameters
            status, label, tenant, cef_mapping = self._validate_ingestion_params(action_result, param)
            if phantom.is_fail(status):
                return action_result.get_status(), processed_params
            processed_params.update({
                "label": label,
                "tenant": tenant,
                "cef_mapping": cef_mapping
            })

        max_results = param.get("max_results")
        ret_val, max_results = self._validate_pagination_parameters(action_result, max_results)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), processed_params
        processed_params.update({
            "max_results": max_results
        })

        tags = param.get("tags", "")
        tags = [x.strip() for x in tags.split(",")]
        tags = ",".join(list([tag for tag in tags if tag]))

        categorization_tags = param.get("categorization_tags", "")
        categorization_tags = [x.strip() for x in categorization_tags.split(",")]
        categorization_tags = ",".join(list([ctag for ctag in categorization_tags if ctag]))

        processed_params.update({
            "tags": tags,
            "categorization_tags": categorization_tags
        })

        reporter_id = None
        reporter_email = param.get("reporter_email")
        if reporter_email:
            # Fetch the reporter ID for the provided email
            status, reporter_id = self._get_reporter_from_email(action_result, reporter_email)
            if phantom.is_fail(status):
                return action_result.get_status(), processed_params
            processed_params["reporter_id"] = reporter_id

        return phantom.APP_SUCCESS, processed_params

    def _manage_data_duplication(self, data, date_key, max_results, total_ingested, limit):
        config = self.get_config()
        index = 0 if (config["sort"] == "latest_first") else -1
        self._state[date_key] = data[index].get("attributes", {}).get("updated_at")
        self.save_state(self._state)

        if max_results:
            if config["sort"] == "latest_first" or self._less_data:
                return None, None
            total_ingested += max_results - self._dup_data
            self._remaining = limit - total_ingested
            if total_ingested >= limit:
                return None, None
            next_cycle_repeat_data = 0
            last_modified_time = data[-1]["attributes"]["updated_at"]
            for x in reversed(data):
                if x["attributes"]["updated_at"] == last_modified_time:
                    next_cycle_repeat_data += 1
                else:
                    break

            max_results = next_cycle_repeat_data + self._remaining
            return max_results, total_ingested
        else:
            return None, None

    def _get_report_params(self, processed_params):
        """
        Get parameters for reports endpoint from processed parameters.

        :param processed_params: dictionary of processed parameters
        :return: params: dictionary of parameters
        """
        params = dict()

        location = processed_params.get("location")
        if location and location.lower() == "all":
            processed_params.pop("location")

        for k, v in list(COFENSE_REPORT_FILTER_MAPPING.items()):
            value = processed_params.get(k)
            if value or value == 0:
                params[v] = value

        params["sort"] = "updated_at" if processed_params.get("sort") == "oldest_first" else "-updated_at"

        return params

    def _process_reports(self, param, action_result):
        """
        Process the reports.

        :param action_result: object of ActionResult class
        :param param: dictionary of params
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, reports
        """
        reports = list()

        self.save_progress(COFENSE_PARAM_VALIDATION_MSG)
        self.debug_print(COFENSE_PARAM_VALIDATION_MSG)
        status, processed_params = self._validate_process_reports_parameters(param, action_result)
        if phantom.is_fail(status):
            return action_result.get_status(), reports

        # Get parameters for endpoint
        params = self._get_report_params(processed_params)

        max_results = processed_params.get("max_results")
        category_id = processed_params.get("category_id")
        reporter_id = processed_params.get("reporter_id")
        ingest_subfields = processed_params.get("ingest_subfields")
        label = processed_params.get("label")
        tenant = processed_params.get("tenant")
        cef_mapping = processed_params.get("cef_mapping")
        ingest = processed_params.get("ingest")

        total_ingested = 0
        limit = max_results
        is_scheduled_poll = self._is_on_poll and not self._is_poll_now
        while True:
            self._dup_data = 0
            self.save_progress(COFENSE_RETRIEVING_DATA_MSG.format("reports"))
            self.debug_print(COFENSE_RETRIEVING_DATA_MSG.format("reports"))
            # Fetch the data
            status, reports = self._paginator(action_result, COFENSE_REPORTS_ENDPOINT, params, max_results, category_id, reporter_id)
            if phantom.is_fail(status):
                return action_result.get_status(), reports

            if not reports:
                return phantom.APP_SUCCESS, reports

            # Ingest the data
            if ingest:
                self._ingest_data(action_result, ingest_subfields, reports, label, tenant, cef_mapping, "report", COFENSE_REPORT_LAST_INGESTED_DATE_STRING)

            if is_scheduled_poll:
                date_string = COFENSE_REPORT_LAST_INGESTED_DATE_STRING
                max_results, total_ingested = self._manage_data_duplication(reports, date_string, max_results, total_ingested, limit)
                if not max_results:
                    break
                params[COFENSE_START_DATE_FILTER] = self._state[COFENSE_REPORT_LAST_INGESTED_DATE_STRING]
            else:
                break

        return phantom.APP_SUCCESS, reports

    def _handle_test_connectivity(self, param):
        """
        Validate the asset configuration for connectivity using supplied configuration.

        :param param: dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # generate new access token
        ret_val = self._generate_new_access_token(action_result=action_result)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Access token received")

        headers = {
            'Accept': COFENSE_ACCEPT_HEADER,
            'Authorization': COFENSE_AUTHORIZATION_HEADER.format(self._access_token)
        }

        url = "{0}{1}".format(self._base_url, COFENSE_TRIAGE_STATUS_ENDPOINT)

        ret_val, _ = self._make_rest_call_oauth2(url, action_result, params=param, headers=headers)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _generate_new_access_token(self, action_result):
        """
        Generate a new access token.

        :param action_result: object of ActionResult class
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        data = {
            'client_id': self._client_id,
            'client_secret': self._client_secret,
            'grant_type': 'client_credentials',
        }

        url = "{0}{1}".format(self._base_url, COFENSE_TRIAGE_TOKEN_ENDPOINT)

        ret_val, resp_json = self._make_rest_call_oauth2(url, action_result, data=data, method="post")

        if phantom.is_fail(ret_val):
            self._state.pop(COFENSE_OAUTH_TOKEN_STRING, {})
            return action_result.get_status()

        self._state[COFENSE_OAUTH_TOKEN_STRING] = resp_json
        self._access_token = resp_json[COFENSE_OAUTH_ACCESS_TOKEN_STRING]
        self.save_state(self._state)

        return phantom.APP_SUCCESS

    def _handle_categorize_report(self, param):
        self.save_progress(COFENSE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        response_id = param.get('response_id')

        # Validate 'response_id' parameter
        ret_val, response_id = self._validate_integer(action_result, response_id, "'response_id'", allow_zero=True)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        category_id = param.get('category_id')

        # Validate 'category_id' parameter
        ret_val, category_id = self._validate_integer(action_result, category_id, "'category_id'", allow_zero=True)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        category_name = param.get('category_name')

        # Check whether category_id or category_name is available or not.
        if not ((category_id or category_id == 0) or category_name):
            return action_result.set_status(phantom.APP_ERROR, COFENSE_CATEGORY_ID_NAME_NOT_EXIST_ERR_MSG)

        report_id = param['report_id']

        # Validate 'report_id' parameter
        ret_val, report_id = self._validate_integer(action_result, report_id, COFENSE_REPORT_ID_STRING, allow_zero=True)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        url = COFENSE_CATEGORIZE_REPORT_ENDPOINT.format(report_id=report_id)

        headers = {
            'Accept': COFENSE_ACCEPT_HEADER,
            'Content-Type': COFENSE_CONTENT_TYPE_HEADER,
            'Authorization': 'Bearer {}'.format(self._access_token)
        }

        # Create list of categorization tags from comma-separated string
        categorization_tags = param.get('categorization_tags', "")
        categorization_tags = [x.strip() for x in categorization_tags.split(',')]
        categorization_tags = list(filter(None, categorization_tags))

        # Get category_id using category_name.
        if category_name and not (category_id or category_id == 0):
            get_category_id_url = COFENSE_GET_CATEGORY_ID_BY_CATEGORY_NAME.format(category_name=category_name)
            ret_val, resp_json = self._make_rest_call_helper_oauth2(action_result, endpoint=get_category_id_url, headers=headers)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            res = resp_json.get('data', [])

            if not res:
                return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_PARAMETER.format("'category_name'"))

            category_id = int(res[0]['id'])

        data = {"data": {"category_id": category_id, "categorization_tags": categorization_tags,
                         "response_id": response_id}}

        ret_val, resp_json = self._make_rest_call_helper_oauth2(
            action_result, endpoint=url, json=data, headers=headers, method='post')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, COFENSE_CATEGORIZE_REPORT_SUCC_MSG)

    def _handle_get_reports(self, param):
        """
        Retrieve the reports that match the specified parameters from Cofense Triage Platform.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(COFENSE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        status, reports = self._process_reports(param, action_result)
        if phantom.is_fail(status):
            return action_result.get_status()

        if not reports:
            return action_result.set_status(phantom.APP_SUCCESS, "No reports found")

        for report in reports:
            action_result.add_data(report)
        action_result.update_summary({"total_reports_retrieved": len(reports)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_report(self, param):
        """
        Retrieve a report with the specified ID from the Cofense Triage Platform.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(COFENSE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        report_id = param["report_id"]
        # Validate 'report_id' parameter
        ret_val, report_id = self._validate_integer(action_result, report_id, COFENSE_REPORT_ID_STRING)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ingest = param.get("ingest_report", False)
        ingest_subfields = param.get("ingest_subfields", False)

        if ingest or ingest_subfields:
            # Validate ingestion parameters
            status, label, tenant, cef_mapping = self._validate_ingestion_params(action_result, param)
            if phantom.is_fail(status):
                return action_result.get_status()

        # Fetch the data
        status, response = self._make_rest_call_helper_oauth2(action_result, COFENSE_REPORT_ENDPOINT.format(report_id=report_id))
        if phantom.is_fail(status):
            return action_result.get_status()

        report = response.get("data", {})

        if not report:
            return action_result.set_status(phantom.APP_SUCCESS, "No report found")

        action_result.add_data(report)

        # Ingest the data
        if ingest or ingest_subfields:
            self._ingest_data(action_result, ingest_subfields, [report], label, tenant, cef_mapping, "report", COFENSE_REPORT_LAST_INGESTED_DATE_STRING)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved the report")

    def _validate_reputation_score(self, action_result, reputation_scores):
        """
        Validate the reputation score.

        :param action_result: object of ActionResult class
        :param reputation_score: string of reputation scores
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), string of reputation scores
        """
        reputation_scores = [x.strip() for x in reputation_scores.split(",")]
        rscores = list()
        for rscore in reputation_scores:
            if rscore:
                try:
                    if not float(rscore).is_integer():
                        return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_INTEGER_LIST_ERR_MSG.format("'reputation_score'")), None

                    rscore = int(rscore)
                    rscores.append(str(rscore))
                except:
                    return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_INTEGER_LIST_ERR_MSG.format("'reputation_score'")), None

        return phantom.APP_SUCCESS, ",".join(rscores)

    def _handle_get_reporters(self, param):
        """
        Fetch reporter(s) from Cofense Triage.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(COFENSE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        vip = param.get("vip", False)

        reputation_scores = param.get("reputation_score", "")
        status, reputation_scores = self._validate_reputation_score(action_result, reputation_scores)
        if phantom.is_fail(status):
            return action_result.get_status()

        email = param.get("email")
        sort = param.get("sort", "oldest_first")
        if sort not in COFENSE_SORT_VALUES:
            return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_PARAMETER.format(COFENSE_SORT_STRING))

        max_results = param.get("max_results")
        # Validate pagination parameters
        ret_val, max_results = self._validate_pagination_parameters(action_result, max_results)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        params = {
            "filter[vip]": vip,
            "filter[reputation_score]": reputation_scores,
            "filter[email]": email,
            "sort": "id" if sort == "oldest_first" else "-id"
        }

        # Remove empty filters from params
        for key, value in list(params.items()):
            if not value:
                params.pop(key)

        status, reporters = self._paginator(action_result, COFENSE_REPORTERS_ENDPOINT, params, max_results)
        if phantom.is_fail(status):
            return action_result.get_status()

        for reporter in reporters:
            action_result.add_data(reporter)

        action_result.update_summary({"total_reporters_retrieved": len(reporters)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_reporter(self, param):
        """
        Fetch the reporter for the provided reporter ID.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(COFENSE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        reporter_id = param["reporter_id"]
        # Validate 'reporter_id' parameter
        ret_val, reporter_id = self._validate_integer(action_result, reporter_id, "'reporter_id'")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        status, response = self._make_rest_call_helper_oauth2(action_result, COFENSE_REPORTER_ENDPOINT.format(reporter_id=reporter_id))
        if phantom.is_fail(status):
            return action_result.get_status()

        action_result.add_data(response.get("data", {}))

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved the reporter")

    def _handle_get_urls(self, param):
        """
        Fetch URL(s) from the Cofense Triage Platform.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(COFENSE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        risk_score = param.get("risk_score")
        # Validate 'risk_score' parameter
        ret_val, risk_score = self._validate_integer(action_result, risk_score, "'risk_score'", True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        rs_operator = param.get("risk_score_operator", "eq")
        if rs_operator not in COFENSE_OPERATORS:
            return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_PARAMETER.format("'risk_score_operator'"))

        url_value = param.get("url_value")
        start_date = param.get("start_date")
        end_date = param.get("end_date")
        # Validate datetime parameters
        status = self._validate_datetime_parameters(action_result, start_date, end_date)
        if phantom.is_fail(status):
            return action_result.get_status()

        sort = param.get("sort", "oldest_first")
        if sort not in COFENSE_SORT_VALUES:
            return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_PARAMETER.format(COFENSE_SORT_STRING))

        max_results = param.get("max_results")
        # Validate pagination parameters
        ret_val, max_results = self._validate_pagination_parameters(action_result, max_results)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        params = {
            "filter[url]": url_value,
            "filter[risk_score_{}]".format(rs_operator): risk_score,
            "filter[updated_at_gteq]": start_date,
            "filter[updated_at_lt]": end_date,
            "sort": "updated_at" if sort == "oldest_first" else "-updated_at"
        }

        # Remove empty filters from params
        for key, value in list(params.items()):
            if value is None or value == "":
                params.pop(key)

        status, urls = self._paginator(action_result, COFENSE_URLS_ENDPOINT, params, max_results)
        if phantom.is_fail(status):
            return action_result.get_status()

        for url in urls:
            action_result.add_data(url)

        action_result.update_summary({"total_urls_retrieved": len(urls)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_url(self, param):
        """
        Fetch URL for the provided URL ID.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(COFENSE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        url_id = param["url_id"]
        # Validate 'url_id' parameter
        ret_val, url_id = self._validate_integer(action_result, url_id, "'url_id'")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        status, response = self._make_rest_call_helper_oauth2(action_result, COFENSE_URL_ENDPOINT.format(url_id=url_id))
        if phantom.is_fail(status):
            return action_result.get_status()

        action_result.add_data(response.get("data", {}))

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved the URL")

    def _validate_get_threat_indicators_params(self, param, action_result):
        """
        Validate parameters of get_threat_indicators method.

        :param param: dictionary of parameters
        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, processed_parameters
        """
        processed_params = dict()

        # Validate 'level' parameter
        level = param.get("level")
        if level and level.lower() not in COFENSE_LEVEL_VALUES:
            return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_PARAMETER.format("'level'")), processed_params

        # Validate 'type' parameter
        typ = param.get("type")
        if typ and typ.lower() not in COFENSE_TYPE_VALUES:
            return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_PARAMETER.format(COFENSE_TYPE_STRING)), processed_params

        source = param.get("source")
        value = param.get("value")

        processed_params.update({
            "level": level,
            "type": typ,
            "source": source,
            "value": value
        })

        # Validate 'start date' and 'end date'
        start_date = param.get("start_date")
        end_date = param.get("end_date")
        status = self._validate_datetime_parameters(
            action_result, start_date, end_date)
        if phantom.is_fail(status):
            return action_result.get_status(), processed_params
        processed_params.update({
            "start_date": start_date,
            "end_date": end_date
        })

        # Validate 'sort' parameter
        sort = param.get("sort", "oldest_first")
        if sort not in COFENSE_SORT_VALUES:
            return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_PARAMETER.format("'sort'")), processed_params

        ingest_threat_indicator = param.get("ingest_threat_indicator", False)
        ingest_subfields = param.get("ingest_subfields", False)
        ingest = ingest_threat_indicator or ingest_subfields
        processed_params.update({
            "sort": sort,
            "ingest_subfields": ingest_subfields,
            "ingest": ingest
        })

        if ingest:
            # Validate ingestion parameters
            status, label, tenant, cef_mapping = self._validate_ingestion_params(
                action_result, param)
            if phantom.is_fail(status):
                return action_result.get_status(), processed_params
            processed_params.update({
                "label": label,
                "tenant": tenant,
                "cef_mapping": cef_mapping
            })

        # Validate pagination parameters
        max_results = param.get("max_results")
        ret_val, max_results = self._validate_pagination_parameters(
            action_result, max_results)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), processed_params
        processed_params.update({
            "max_results": max_results
        })

        return phantom.APP_SUCCESS, processed_params

    def _get_threat_indicators_params(self, processed_params):
        """
        Get parameters for 'get threat indicators' endpoint from proccessed parameters.

        :param processed_params: dictionary of processed parameters
        :return: params: dictionary of parameters
        """
        params = dict()

        level = processed_params.get("level")
        if level and level.lower() == "all":
            processed_params.pop("level")

        threat_type = processed_params.get("type")
        if threat_type and threat_type.lower() == "all":
            processed_params.pop("type")

        for k, v in list(COFENSE_THREAT_FILTER_MAPPING.items()):
            val = processed_params.get(k)
            if val:
                params[v] = val

        params["sort"] = "updated_at" if processed_params.get(
            "sort") == "oldest_first" else "-updated_at"

        return params

    def _process_threat_indicators(self, param, action_result):
        """
        Process the threat indicators.

        :param action_result: object of ActionResult class
        :param param: dictionary of params
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, reports
        """
        threat_indicators = list()
        endpoint = COFENSE_THREAT_INDICATORS_ENDPOINT

        self.save_progress(COFENSE_PARAM_VALIDATION_MSG)
        self.debug_print(COFENSE_PARAM_VALIDATION_MSG)
        # Validate parameters
        status, processed_params = self._validate_get_threat_indicators_params(
            param, action_result)
        if phantom.is_fail(status):
            return action_result.get_status(), threat_indicators

        # Get parameters for endpoint
        params = self._get_threat_indicators_params(processed_params)

        max_results = processed_params.get('max_results')
        ingest = processed_params.get('ingest')
        ingest_subfields = processed_params.get('ingest_subfields')
        total_ingested = 0
        limit = max_results
        is_scheduled_poll = self._is_on_poll and not self._is_poll_now

        while True:
            self._dup_data = 0
            self.save_progress(COFENSE_RETRIEVING_DATA_MSG.format("threat indicators"))
            self.debug_print(COFENSE_RETRIEVING_DATA_MSG.format("threat indicators"))
            # Fetch the data
            status, threat_indicators = self._paginator(action_result, endpoint, params=params, max_results=max_results)
            if phantom.is_fail(status):
                return action_result.get_status(), threat_indicators

            if not threat_indicators:
                return phantom.APP_SUCCESS, threat_indicators

            # Ingest the data
            if ingest:
                self._ingest_data(action_result, ingest_subfields, threat_indicators, processed_params.get(
                    'label'), processed_params.get('tenant'), processed_params.get('cef_mapping'), "threat indicator", COFENSE_THREAT_LAST_INGESTED_DATE_STRING)

            if is_scheduled_poll:
                date_string = COFENSE_THREAT_LAST_INGESTED_DATE_STRING
                max_results, total_ingested = self._manage_data_duplication(threat_indicators, date_string, max_results, total_ingested, limit)
                if not max_results:
                    break
                params[COFENSE_START_DATE_FILTER] = self._state[COFENSE_THREAT_LAST_INGESTED_DATE_STRING]
            else:
                break

        return phantom.APP_SUCCESS, threat_indicators

    def _handle_get_threat_indicators(self, param):
        """
        Fetch a list of threat indicator(s) that match the specified parameters from the Cofense Triage Platform.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(COFENSE_ACTION_HANDLER_MSG.format(
            self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        status, threat_indicators = self._process_threat_indicators(param, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        if not threat_indicators:
            return action_result.set_status(phantom.APP_SUCCESS, "No threat indicators found")

        for threat_indicator in threat_indicators:
            action_result.add_data(threat_indicator)
        action_result.update_summary(
            {"total_threat_indicators_retrieved": len(threat_indicators)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _validate_email(self, input_data):

        # Truncate extra commas
        input_data = input_data.strip(',')
        # ignore if contains only commas
        if not input_data:
            return True

        emails = input_data.split(',')
        for email in emails:
            if (not ph_utils.is_email(email.strip())):
                return False
        return True

    def _handle_create_response(self, param):
        """
        Create a response.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(COFENSE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # initialize the parameters
        name = param['name']
        subject = param['subject']
        body = param['body']

        description = param.get('description')
        attach_original = param.get('attach_original', False)

        to_reporter = param.get('to_reporter', True)
        to_other = param.get('to_other', False)

        to_other_address = param.get('to_other_address')
        cc_address = param.get('cc_address')
        bcc_address = param.get('bcc_address')

        # check if either to_reporter or to_other is enabled
        if not (to_reporter or to_other):
            return action_result.set_status(phantom.APP_ERROR, "Please enable either 'to_reporter', 'to_other' or both")

        # check if to_other_address is present if to_other is enabled
        if to_other and not to_other_address:
            return action_result.set_status(phantom.APP_ERROR,
                                            "Please provide valid email in 'to_other_address' if 'to_other' is enabled")
        # populate the attribute dictionary
        attributes = dict()
        attributes.update({
            "name": name,
            "subject": subject,
            "body": body,
            "attach_original": attach_original,
            "to_reporter": to_reporter,
            "to_other": to_other
        })
        if description:
            attributes.update({
                "description": description
            })
        if to_other_address:
            attributes.update({
                "to_other_address": to_other_address.strip(',')
            })
        if cc_address:
            attributes.update({
                "cc_address": cc_address.strip(',')
            })
        if bcc_address:
            attributes.update({
                "bcc_address": bcc_address.strip(',')
            })

        # populate the data dictionary to be sent in the request
        data = {
            "data": {
                "type": "responses",
                "attributes": attributes
            }
        }
        # populate the headers to be sent in the request
        headers = {
            'Accept': COFENSE_ACCEPT_HEADER,
            'Content-Type': COFENSE_CONTENT_TYPE_HEADER
        }

        ret_val, resp_json = self._make_rest_call_helper_oauth2(
            action_result, endpoint=COFENSE_RESPONSE_ENDPOINT, json=data, headers=headers, method='post')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        response = resp_json.get("data")
        action_result.add_data(response)

        response_id = response["id"]
        summary_data["response_id"] = response_id

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully created the response.")

    def _handle_get_responses(self, param):
        """
        Get the responses.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(COFENSE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        max_results = param.get("max_results")

        ret_val, max_results = self._validate_pagination_parameters(action_result, max_results)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        status, responses = self._paginator(action_result, COFENSE_RESPONSE_ENDPOINT, max_results=max_results)
        if phantom.is_fail(status):
            return action_result.get_status()

        for response in responses:
            action_result.add_data(response)
        action_result.update_summary({"total_responses_retrieved": len(responses)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_email(self, param):
        """
        Get the email.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(COFENSE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        report_id = param["report_id"]

        ret_val, report_id = self._validate_integer(action_result, report_id, COFENSE_REPORT_ID_STRING)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.save_progress("Downloading raw email of report id {}".format(report_id))
        ret_val, response = self._make_rest_call_helper_oauth2(
            action_result, endpoint=COFENSE_EMAIL_ENDPOINT.format(report_id=report_id))

        if phantom.is_fail(ret_val):
            self.save_progress("Error: failed to download raw email; REST error")
            return action_result.get_status()

        method = param['download_method']

        if method.lower() not in ('artifact', 'vaulted file'):
            return action_result.set_status(phantom.APP_ERROR, "Please enter either 'artifact' or 'vaulted file' in 'download_method' action parameter")

        filename = self._r.headers.get(
            'Content-Disposition', "").split('filename=')[-1].strip('"')
        source_data_identifier = "report id  {0}".format(report_id)

        if method.lower() == "artifact":
            ret_val, summary, data = self._save_email_artifact(
                action_result, source_data_identifier=source_data_identifier, filename=filename, content=response)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
        else:
            ret_val, summary, data = self._vault_file(action_result, filename=filename, content=response,
                                                      makeartifact=source_data_identifier if param.get('create_vaulted_file_artifact', False) else None)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        summary['report_id'] = report_id
        data['report_id'] = report_id
        action_result.update_summary(summary)
        action_result.add_data(data)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _save_email_artifact(self, action_result, source_data_identifier=None, filename=None, content=None):

        if not source_data_identifier or not filename or not content:
            return action_result.set_status(phantom.APP_ERROR, "Error: one or more arguments are null value"), None, None

        ret_val, message, artifact_id = self.save_artifacts(artifacts=[{
            'name': "Email Artifact",
            'source_data_identifier': source_data_identifier,
            'container_id': self.get_container_id(),
            'type': "email",
            'cef': {
                '_raw_email': content.decode("utf-8"),
                'filename': filename,
            }
        }])

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, message), None, None

        summary = {
            'artifact_id': artifact_id[0],
            'filename': filename,
        }

        data = summary.copy()
        data['size'] = len(content)

        return phantom.APP_SUCCESS, summary, data

    def _vault_file(self, action_result, filename=None, content=None, makeartifact=False):

        if not filename or not content:
            return action_result.set_status(phantom.APP_ERROR, "Error: one or more arguments are null value"), None, None

        if hasattr(Vault, 'get_vault_tmp_dir'):
            tmp = tempfile.NamedTemporaryFile(mode="wb", dir=Vault.get_vault_tmp_dir(), delete=False)
        else:
            tmp = tempfile.NamedTemporaryFile(mode="wb", dir=PHANTOM_VAULT_DIR, delete=False)

        tmp.write(content)
        tmp.close()

        try:
            success, _, vault_id = ph_rules.vault_add(file_location=tmp.name, container=self.get_container_id(), file_name=filename)
        except:
            return action_result.set_status(phantom.APP_ERROR, "Error: Unable to add the file to vault"), None, None

        if not success:
            return action_result.set_status(phantom.APP_ERROR, "Error: Unable to add the file to vault"), None, None

        try:
            _, _, fileinfo = ph_rules.vault_info(vault_id=vault_id, container_id=self.get_container_id())
            fileinfo = list(fileinfo)
        except:
            return action_result.set_status(phantom.APP_ERROR,
                                            "Error: Vault file error, newly vaulted file not found; {}".format(vault_id)), None, None

        if len(fileinfo) == 0:
            return action_result.set_status(phantom.APP_ERROR,
                                            "Error: Vault file error, newly vaulted file not found; {}".format(vault_id)), None, None
        fileinfo = fileinfo[0]

        summary = {
            'vault_id': vault_id,
            'filename': filename,
        }

        data = {
            'vault_id': vault_id,
            'filename': fileinfo.get('name'),
            'size': fileinfo.get('size'),
            'sha1': fileinfo.get('metadata', {}).get('sha1'),
            'sha256': fileinfo.get('metadata', {}).get('sha256'),
            'md5': fileinfo.get('metadata', {}).get('md5'),
            'vaulted': fileinfo.get('path'),
        }

        if makeartifact:
            ret_val, message, artifact_id = self.save_artifacts(artifacts=[{
                'name': "Vault Artifact",
                'source_data_identifier': makeartifact,
                'container_id': self.get_container_id(),
                'type': "vault",
                'cef': data,
            }])
            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR, message), None, None

            summary['artifact_id'] = artifact_id[0]
            data['artifact_id'] = artifact_id[0]

        return phantom.APP_SUCCESS, summary, data

    def _handle_create_threat_indicator(self, param):
        """
        Create a threat indicator.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(COFENSE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        threat_level = param["level"]
        if threat_level.lower() not in COFENSE_THREAT_LEVELS:
            return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_PARAMETER.format("'level'"))

        threat_type = param["type"]
        if threat_type.lower() not in COFENSE_THREAT_TYPES:
            return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_PARAMETER.format(COFENSE_TYPE_STRING))

        threat_value = param["value"]

        threat_source = param.get("source", COFENSE_DEFAULT_THREAT_SOURCE)

        data = {
            "data": {
                "type": "threat_indicators",
                "attributes": {
                    "threat_level": threat_level,
                    "threat_type": threat_type,
                    "threat_value": threat_value,
                    "threat_source": threat_source
                }
            }
        }

        headers = {
            'Accept': COFENSE_ACCEPT_HEADER,
            'Content-Type': COFENSE_CONTENT_TYPE_HEADER,
            'Authorization': COFENSE_AUTHORIZATION_HEADER.format(self._access_token)
        }

        status, response = self._make_rest_call_helper_oauth2(action_result, COFENSE_THREAT_INDICATORS_ENDPOINT, headers, json=data, method="post")
        if phantom.is_fail(status):
            return action_result.get_status()

        data = response.get("data", {})
        action_result.add_data(data)
        action_result.update_summary({"threat_indicator_id": data.get("id")})

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully created the threat indicator")

    def _handle_get_categories(self, param):
        """
        Fetch the categories.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(COFENSE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        name = param.get("name")
        malicious = param.get("malicious", False)

        max_results = param.get("max_results")
        ret_val, max_results = self._validate_pagination_parameters(action_result, max_results)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        params = dict()
        if name:
            params["filter[name_cont]"] = name
        if malicious:
            params["filter[malicious]"] = True

        status, categories = self._paginator(action_result, COFENSE_CATEGORIES_ENDPOINT, params, max_results)
        if phantom.is_fail(status):
            return action_result.get_status()

        for category in categories:
            action_result.add_data(category)

        action_result.update_summary({"total_categories_retrieved": len(categories)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _poll_for_reports(self, action_result, params, config):
        """
        Perform the on poll ingest functionality for reports.

        :param action_result: object of ActionResult class
        :param params: Dictionary of input parameters
        :param config: Dictionary of asset configuration parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        params["location"] = config.get("report_location")
        params["ingest_report"] = True
        if self._is_poll_now:
            params["start_date"] = config.get('start_date')
        else:
            params["start_date"] = self._state.get(COFENSE_REPORT_LAST_INGESTED_DATE_STRING, config.get('start_date'))

        for key in COFENSE_INGESTION_REPORT_KEYS:
            params[key] = config.get(key)
        for key, value in list(params.items()):
            if not value:
                params.pop(key)
        status, _ = self._process_reports(params, action_result)
        if phantom.is_fail(status):
            return action_result.get_status()

        return phantom.APP_SUCCESS

    def _poll_for_threats(self, action_result, params, config):
        """
        Perform the on poll ingest functionality for threat indicators.

        :param action_result: object of ActionResult class
        :param params: Dictionary of input parameters
        :param config: Dictionary of asset configuration parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        params["ingest_threat_indicator"] = True
        if self._is_poll_now:
            params["start_date"] = config.get('start_date')
        else:
            params["start_date"] = self._state.get(COFENSE_THREAT_LAST_INGESTED_DATE_STRING, config.get('start_date'))

        params["type"] = config.get("threat_indicator_type")
        params["level"] = config.get("threat_indicator_level")

        for key, value in list(params.items()):
            if not value:
                params.pop(key)
        status, _ = self._process_threat_indicators(params, action_result)
        if phantom.is_fail(status):
            return action_result.get_status()

        return phantom.APP_SUCCESS

    def _handle_on_poll(self, param):
        """
        Perform the on poll ingest functionality.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        config = self.get_config()
        ingestion_type = config.get("ingestion_type")
        if not ingestion_type or ingestion_type not in COFENSE_INGESTION_TYPES:
            return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_PARAMETER.format("'ingestion_type'"))

        update_state_after = config.get("update_state_after", 100)
        # Validate 'update_state_after' parameter
        ret_val, self._update_state_after = self._validate_integer(action_result, update_state_after, "'update_state_after'")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self._is_poll_now = self.is_poll_now()
        self._is_on_poll = True

        params = dict()
        params["label"] = config.get('ingest', {}).get('container_label')
        params["tenant"] = "NONE"

        for key in COFENSE_INGESTION_COMMON_KEYS:
            params[key] = config.get(key)

        if self._is_poll_now:
            params["max_results"] = param.get('container_count', config.get('max_results'))

        if ingestion_type == "reports":
            status = self._poll_for_reports(action_result, params, config)
            if phantom.is_fail(status):
                return action_result.get_status()

        else:
            status = self._poll_for_threats(action_result, params, config)
            if phantom.is_fail(status):
                return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_comments(self, param):
        """
        Fetch comments from the Cofense Triage Platform.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(COFENSE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        body_format = param.get("body_format")
        if body_format:
            body_format = body_format.lower()
            if body_format not in COFENSE_COMMENT_BODY_FORMATS:
                return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_PARAMETER.format("'body_format'"))

        if body_format == "all":
            body_format = None

        tags = param.get("tags", "")
        tags = [x.strip() for x in tags.split(",")]
        tags = ",".join(list([tag for tag in tags if tag]))

        start_date = param.get("start_date")
        end_date = param.get("end_date")
        # Validate datetime parameters
        status = self._validate_datetime_parameters(action_result, start_date, end_date)
        if phantom.is_fail(status):
            return action_result.get_status()

        sort = param.get("sort", "oldest_first")
        if sort not in COFENSE_SORT_VALUES:
            return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_PARAMETER.format(COFENSE_SORT_STRING))

        max_results = param.get("max_results")
        # Validate pagination parameters
        ret_val, max_results = self._validate_pagination_parameters(action_result, max_results)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        params = {
            "filter[body_format]": body_format,
            "filter[tags_any]": tags,
            "filter[updated_at_gteq]": start_date,
            "filter[updated_at_lt]": end_date,
            "sort": "updated_at" if sort == "oldest_first" else "-updated_at"
        }

        # Remove empty filters from params
        for key, value in list(params.items()):
            if not value:
                params.pop(key)

        status, comments = self._paginator(action_result, COFENSE_COMMENTS_ENDPOINT, params, max_results)
        if phantom.is_fail(status):
            return action_result.get_status()

        for comment in comments:
            data = comment.get("relationships", {}).get("commentable", {}).get("data")
            if data:
                new_type = " ".join(data.get("type", "").rstrip("s").split("_"))
                comment["relationships"]["commentable"]["data"]["type"] = new_type
            action_result.add_data(comment)

        action_result.update_summary({"total_comments_retrieved": len(comments)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_comment(self, param):
        """
        Fetch a comment for the provided comment ID.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(COFENSE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        comment_id = param["comment_id"]
        # Validate 'comment_id' parameter
        ret_val, comment_id = self._validate_integer(action_result, comment_id, "'comment_id'")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        status, response = self._make_rest_call_helper_oauth2(action_result, COFENSE_COMMENT_ENDPOINT.format(comment_id=comment_id))
        if phantom.is_fail(status):
            return action_result.get_status()

        comment = response.get("data", {})

        data = comment.get("relationships", {}).get("commentable", {}).get("data")
        if data:
            new_type = " ".join(data.get("type", "").rstrip("s").split("_"))
            comment["relationships"]["commentable"]["data"]["type"] = new_type

        action_result.add_data(comment)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved the comment")

    def _validate_get_rules_parameters(self, param, action_result):
        """
        Validate parameters of get_rules method.

        :param param: dictionary of params
        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, processed_parameters
        """
        processed_params = dict()
        name = param.get("name")
        description = param.get("description")
        processed_params.update({
            "name": name,
            "description": description
        })

        priority = param.get("priority")
        # Validate 'priority' parameter
        ret_val, priority = self._validate_integer(action_result, priority, "'priority'")
        if phantom.is_fail(ret_val):
            return action_result.get_status(), processed_params
        processed_params["priority"] = priority

        tags = param.get("tags", "")
        tags = [x.strip() for x in tags.split(",")]
        tags = ",".join(list([tag for tag in tags if tag]))
        processed_params["tags"] = tags

        scope = param.get("scope")
        author_name = param.get("author_name")
        active = param.get("active", False)
        context = param.get("rule_context")
        if context and context.lower() not in COFENSE_RULE_CONTEXTS:
            msg = COFENSE_INVALID_PARAMETER.format("'rule_context'")
            return action_result.set_status(phantom.APP_ERROR, msg), processed_params

        reports_count = param.get("reports_count")
        # Validate 'reports_count' parameter
        ret_val, reports_count = self._validate_integer(action_result, reports_count, "'reports_count'", True)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), processed_params

        processed_params.update({
            "scope": scope,
            "author_name": author_name,
            "context": context,
            "active": active,
            "reports_count": reports_count
        })

        rc_operator = param.get("reports_count_operator", "eq")
        if rc_operator not in COFENSE_OPERATORS:
            msg = COFENSE_INVALID_PARAMETER.format("'reports_count_operator'")
            return action_result.set_status(phantom.APP_ERROR, msg), processed_params
        processed_params["rc_operator"] = rc_operator

        start_date = param.get("start_date")
        end_date = param.get("end_date")
        status = self._validate_datetime_parameters(action_result, start_date, end_date)
        if phantom.is_fail(status):
            return action_result.get_status(), processed_params
        processed_params.update({
            "start_date": start_date,
            "end_date": end_date
        })

        sort = param.get("sort", "oldest_first")
        if sort not in COFENSE_SORT_VALUES:
            msg = COFENSE_INVALID_PARAMETER.format(COFENSE_SORT_STRING)
            return action_result.set_status(phantom.APP_ERROR, msg), processed_params

        max_results = param.get("max_results")
        ret_val, max_results = self._validate_pagination_parameters(action_result, max_results)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), processed_params
        processed_params.update({
            "sort": sort,
            "max_results": max_results
        })

        return phantom.APP_SUCCESS, processed_params

    def _handle_get_rules(self, param):
        """
        Fetch rules from the Cofense Triage Platform.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(COFENSE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        status, processed_params = self._validate_get_rules_parameters(param, action_result)
        if phantom.is_fail(status):
            return action_result.get_status()

        params = dict()

        context = processed_params.get("context")
        if context and context.lower() == "all":
            processed_params.pop("context")

        # Map parameters to filters
        for k, v in list(COFENSE_RULE_FILTER_MAPPING.items()):
            value = processed_params.get(k)
            if value:
                params[v] = value

        rc = processed_params.get("reports_count")
        if rc is not None:
            key = "filter[reports_count_{}]".format(processed_params["rc_operator"])
            params[key] = rc

        params["sort"] = "updated_at" if processed_params.get("sort") == "oldest_first" else "-updated_at"

        max_results = processed_params.get("max_results")

        status, rules = self._paginator(action_result, COFENSE_RULES_ENDPOINT, params, max_results)
        if phantom.is_fail(status):
            return action_result.get_status()

        for rule in rules:
            action_result.add_data(rule)

        action_result.update_summary({"total_rules_retrieved": len(rules)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_rule(self, param):
        """
        Fetch rule for the provided rule ID.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(COFENSE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        rule_id = param["rule_id"]
        # Validate 'rule_id' parameter
        ret_val, rule_id = self._validate_integer(action_result, rule_id, "'rule_id'")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ingest_report = param.get("ingest_report", False)
        ingest_subfields = param.get("ingest_subfields", False)
        ingest = ingest_report or ingest_subfields
        if ingest:
            # Validate ingestion parameters
            status, label, tenant, cef_mapping = self._validate_ingestion_params(action_result, param)
            if phantom.is_fail(status):
                return action_result.get_status()

        status, response = self._make_rest_call_helper_oauth2(action_result, COFENSE_RULE_ENDPOINT.format(rule_id=rule_id))
        if phantom.is_fail(status):
            return action_result.get_status()

        rule = response.get("data", {})

        if not rule:
            return action_result.set_status(phantom.APP_SUCCESS, "No rule found")

        endpoint = "{}/reports".format(COFENSE_RULE_ENDPOINT.format(rule_id=rule_id))

        # Fetch the reports related to the rule
        status, reports = self._paginator(action_result, endpoint)
        if phantom.is_fail(status):
            return action_result.get_status()

        if not reports:
            rule["reports"] = list()
            action_result.add_data(rule)
            return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved the rule")

        # Ingest the data
        if ingest:
            self._ingest_data(action_result, ingest_subfields, reports, label, tenant, cef_mapping, "report", COFENSE_REPORT_LAST_INGESTED_DATE_STRING)

        rule["reports"] = reports
        action_result.add_data(rule)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved the rule")

    def _handle_get_integration_submissions(self, param):
        """
        Fetch integration submissions.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(COFENSE_ACTION_HANDLER_MSG.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        itg_type = param["type"].lower()
        if itg_type not in COFENSE_INTEGRATION_TYPES:
            return action_result.set_status(phantom.APP_ERROR, COFENSE_INVALID_PARAMETER.format(COFENSE_TYPE_STRING))

        itg_value = param["value"]
        func_name = "is_{}".format(itg_type)
        func = getattr(ph_utils, func_name)
        if not func(itg_value):
            return action_result.set_status(phantom.APP_ERROR, "The provided 'value' doesn't match the provided 'type'")

        if itg_type == "url":
            params = {
                "filter[url]": itg_value
            }
            endpoint = COFENSE_URLS_ENDPOINT
        else:
            params = {
                "filter[{}]".format(itg_type): itg_value
            }
            endpoint = COFENSE_ATTACHMENT_PAYLOADS_ENDPOINT

        status, response = self._paginator(action_result, endpoint, params)
        if phantom.is_fail(status):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_SUCCESS, "No data found for the provided {} value".format(itg_type.upper()))

        response_id = response[0]["id"]

        new_endpoint = "{}{}".format(endpoint, "/{}/integration_submissions".format(response_id))
        status, results = self._paginator(action_result, new_endpoint)
        if phantom.is_fail(status):
            return action_result.get_status()

        for result in results:
            action_result.add_data(result)

        action_result.update_summary({"total_integration_submissions_retrieved": len(results)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """
        Get current action identifier and call member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        # Dictionary mapping each action with its corresponding handler
        action_mapping = {
            "test_connectivity": self._handle_test_connectivity,
            "categorize_report": self._handle_categorize_report,
            "get_reports": self._handle_get_reports,
            "get_report": self._handle_get_report,
            "get_reporters": self._handle_get_reporters,
            "get_reporter": self._handle_get_reporter,
            "get_urls": self._handle_get_urls,
            "get_url": self._handle_get_url,
            "get_threat_indicators": self._handle_get_threat_indicators,
            "create_response": self._handle_create_response,
            "get_responses": self._handle_get_responses,
            "create_threat_indicator": self._handle_create_threat_indicator,
            "get_categories": self._handle_get_categories,
            "get_email": self._handle_get_email,
            "on_poll": self._handle_on_poll,
            "get_comments": self._handle_get_comments,
            "get_comment": self._handle_get_comment,
            "get_rules": self._handle_get_rules,
            "get_rule": self._handle_get_rule,
            "get_integration_submissions": self._handle_get_integration_submissions,
        }

        if action_id in list(action_mapping.keys()):
            action_function = action_mapping[action_id]
            ret_val = action_function(param)

        return ret_val

    def initialize(self):
        """
        Initialize the global variables with its value and validate it.

        This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        if not isinstance(self._state, dict):
            self.debug_print("Reseting the state file with the default format")
            self._state = {
                "app_version": self.get_app_json().get('app_version')
            }
            return self.set_status(phantom.APP_ERROR, COFENSE_STATE_FILE_CORRUPT_ERROR)

        # get the asset config
        config = self.get_config()

        self._base_url = config.get('base_url').rstrip('/')
        self._client_id = config.get('client_id')
        self._client_secret = config.get('client_secret')
        self._access_token = self._state.get(COFENSE_OAUTH_TOKEN_STRING, {}).get(COFENSE_OAUTH_ACCESS_TOKEN_STRING)
        self._verify = config.get('verify_server_cert', False)

        self.set_validator('email', self._validate_email)

        severity_mapping = config.get("category_id_to_severity")
        if severity_mapping:
            try:
                self._category_id_to_severity = json.loads(severity_mapping)
            except:
                return self.set_status(phantom.APP_ERROR, COFENSE_INVALID_JSON_PARAMETER.format("'category ID to severity mapping' configuration"))

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

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = CofenseTriageConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CofenseTriageConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
