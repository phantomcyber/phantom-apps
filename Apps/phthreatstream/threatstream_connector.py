# File: threatstream_connector.py
# Copyright (c) 2016-2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

# Local imports
from threatstream_consts import *

import ast
import os
import uuid
import shutil
import requests
import datetime
import ipaddress
import pythonwhois
from ipwhois import IPWhois
import simplejson as json
from bs4 import BeautifulSoup
from bs4 import UnicodeDammit
from urlparse import urlsplit

# These are the fields outputted in the widget
# Check to see if all of these are in the the
#  the json
# Note that all of these should be in the "admin"
#  field
whois_fields = [ "city",
                 "country",
                 "email",
                 "name",
                 "organization" ]


def _json_fallback(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    else:
        return obj


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class ThreatstreamConnector(BaseConnector):

    ACTION_ID_WHOIS_IP = "whois_ip"
    ACTION_ID_WHOIS_DOMAIN = "whois_domain"
    ACTION_ID_EMAIL_REPUTATION = "email_reputation"
    ACTION_ID_IP_REPUTATION = "ip_reputation"
    ACTION_ID_DOMAIN_REPUTATION = "domain_reputation"
    ACTION_ID_URL_REPUTATION = "url_reputation"
    ACTION_ID_FILE_REPUTATION = "file_reputation"
    ACTION_ID_LIST_INCIDENTS = "list_incidents"
    ACTION_ID_LIST_VULNERABILITY = "list_vulnerabilities"
    ACTION_ID_LIST_OBSERVABLE = "list_observables"
    ACTION_ID_GET_INCIDENT = "get_incident"
    ACTION_ID_GET_OBSERVABLE = "get_observable"
    ACTION_ID_GET_VULNERABILITY = "get_vulnerability"
    ACTION_ID_DELETE_INCIDENT = "delete_incident"
    ACTION_ID_CREATE_INCIDENT = "create_incident"
    ACTION_ID_UPDATE_INCIDENT = "update_incident"
    ACTION_ID_IMPORT_IOC = "import_observables"
    ACTION_ID_IMPORT_EMAIL_OBSERVABLES = "import_email_observable"
    ACTION_ID_IMPORT_FILE_OBSERVABLES = "import_file_observable"
    ACTION_ID_IMPORT_IP_OBSERVABLES = "import_ip_observable"
    ACTION_ID_IMPORT_URL_OBSERVABLES = "import_url_observable"
    ACTION_ID_IMPORT_DOMAIN_OBSERVABLES = "import_domain_observable"
    ACTION_ID_RUN_QUERY = "run_query"
    ACTION_ID_TAG_IOC = "tag_observable"
    ACTION_ID_ON_POLL = "on_poll"
    ACTION_ID_DETONATE_FILE = "detonate_file"
    ACTION_ID_GET_STATUS = "get_status"
    ACTION_ID_GET_REPORT = "get_report"
    ACTION_ID_DETONATE_URL = "detonate_url"
    ACTION_ID_GET_PCAP = "get_pcap"

    def __init__(self):

        super(ThreatstreamConnector, self).__init__()
        self._base_url = None
        self._state = None
        self._verify = None
        self._is_cloud_instance = None
        self._first_run_limit = None
        self._data_dict = {}  # Blank dict to contain data from all API calls
        return

    def initialize(self):
        config = self.get_config()

        self._base_url = "https://{0}/api".format(UnicodeDammit(config.get('hostname', 'api.threatstream.com')).unicode_markup.encode('utf-8'))
        self._state = self.load_state()
        self._verify = config.get("verify_server_cert")
        self._is_cloud_instance = config.get("is_cloud_instance")
        self._first_run_limit = config.get('first_run_containers')

        if self._first_run_limit == 0 or (self._first_run_limit and (not str(self._first_run_limit).isdigit() or self._first_run_limit <= 0)):
            return self.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="first_run_containers"))

        self.set_validator('ipv6', self._is_ip)

        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code
        action = self.get_action_identifier()

        if 200 <= status_code < 399:

            if status_code == 202:
                return RetVal(phantom.APP_SUCCESS, {})
            elif status_code == 204 and action == self.ACTION_ID_DELETE_INCIDENT:
                return RetVal(action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted incident"), {})
            else:
                try:
                    resp = response.json()
                    return RetVal(phantom.APP_SUCCESS, resp)
                except:
                    if not response.text:
                        resp_text = "Unknown response from the server"
                    else:
                        resp_text = response.text
                    action_result.set_status(phantom.APP_SUCCESS, "Unable to parse the JSON response. Response Status Code: {}. Response: {}".format(
                                                status_code, UnicodeDammit(resp_text).unicode_markup.encode('utf-8')))
                    return RetVal(phantom.APP_SUCCESS, {})

        data_message = ""
        if not response.text:
            data_message = "Empty response and no information in the header"
        else:
            try:
                soup = BeautifulSoup(response.text, "html.parser")
                error_text = soup.text
                split_lines = error_text.split('\n')
                split_lines = [x.strip() for x in split_lines if x.strip()]
                error_text = '\n'.join(split_lines)
            except:
                error_text = "Cannot parse error details"

            # Error text can still be an empty string
            if error_text:
                data_message = " Data from server:\n{0}\n".format(UnicodeDammit(error_text).unicode_markup.encode('utf-8'))

        message = "Status Code: {0}. {1}".format(status_code, data_message)

        message = message.replace('{', '{{').replace('}', '}}')

        if len(message) > 500:
            message = "Status Code: {0}. Error while connecting to the server. Please check the asset and the action's input parameters".format(status_code)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            if resp_json.get('error', None) is None:
                return RetVal(phantom.APP_SUCCESS, resp_json)

        if not r.text:
            message = "Status Code: {0}. {1}".format(r.status_code, "Empty response and no information in the header")
        else:
            # You should process the error returned in the json
            message = "Error from server. Status Code: {0} Data from server: {1}".format(
                    r.status_code, UnicodeDammit(r.text.replace('{', '{{').replace('}', '}}')).unicode_markup.encode('utf-8'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

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
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, UnicodeDammit(r.text.replace('{', '{{').replace('}', '}}')).unicode_markup.encode('utf-8'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, action_result, endpoint, payload=None, headers=None, data=None, method="get", files=None, use_json=True):

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = "{0}{1}".format(self._base_url, endpoint)

        if use_json:
            try:
                r = request_func(
                                url,
                                json=data,
                                headers=headers,
                                params=payload,
                                verify=self._verify,
                                files=files)
            except Exception as e:
                if e.message:
                    if isinstance(e.message, basestring):
                        error_msg = UnicodeDammit(e.message).unicode_markup.encode('UTF-8').replace(payload.get('api_key'), '<api_key_value_provided_in_config_params>')
                    else:
                        try:
                            error_msg = UnicodeDammit(e.message).unicode_markup.encode('utf-8').replace(payload.get('api_key'), '<api_key_value_provided_in_config_params>')
                        except:
                            error_msg = "Unknown error occurred. Please check the asset configuration and|or the action parameters."
                else:
                    error_msg = "Unknown error occurred. Please check the asset configuration and|or the action parameters."

                return RetVal(action_result.set_status(phantom.APP_ERROR, "Error making rest call to server. Details: {0}"
                                                    .format(error_msg)), resp_json)

        else:
            try:
                r = request_func(
                                url,
                                data=data,
                                headers=headers,
                                params=payload,
                                verify=self._verify,
                                files=files)
            except Exception as e:
                if e.message:
                    if isinstance(e.message, basestring):
                        error_msg = UnicodeDammit(e.message).unicode_markup.encode('UTF-8').replace(payload.get('api_key'), '<api_key_value_provided_in_config_params>')
                    else:
                        try:
                            error_msg = UnicodeDammit(e.message).unicode_markup.encode('utf-8').replace(payload.get('api_key'), '<api_key_value_provided_in_config_params>')
                        except:
                            error_msg = "Unknown error occurred. Please check the asset configuration and|or the action parameters."
                else:
                    error_msg = "Unknown error occurred. Please check the asset configuration and|or the action parameters."

                return RetVal(action_result.set_status(phantom.APP_ERROR, "Error making rest call to server. Details: {0}"
                                                    .format(error_msg)), resp_json)

        ret_val, response = self._process_response(r, action_result)

        current_message = action_result.get_message()

        if current_message:
            current_message = current_message.replace(payload.get('api_key'), '<api_key_value_provided_in_config_params>')

        if phantom.is_fail(ret_val):
            return RetVal(action_result.set_status(phantom.APP_ERROR, current_message), response)
        else:
            return RetVal(action_result.set_status(phantom.APP_SUCCESS, current_message), response)

    def _is_ip(self, input_ip_address):
        """ Function that checks given address and return True if address is valid IPv4 or IPV6 address.

        :param input_ip_address: IP address
        :return: status (success/failure)
        """

        ip_address_input = input_ip_address

        try:
            ipaddress.ip_address(unicode(ip_address_input))
        except:
            return False

        return True

    def _generate_payload(self, **kwargs):
        """Create dict with username and password URL parameters
           Can also add in any further URL parameters
        """
        payload = {}
        config = self.get_config()
        payload['username'] = config[THREATSTREAM_JSON_USERNAME]
        payload['api_key'] = config[THREATSTREAM_JSON_API_KEY]
        for k, v in kwargs.iteritems():
            payload[k] = v
        return payload

    def _intel_details(self, value, action_result, limit=None):
        """ Use the intelligence endpoint to get general details """

        # strip out scheme because API cannot find
        # intel with it included
        if phantom.is_url(value):
            host = urlsplit(value).netloc
            value_regexp = r'.*{0}.*'.format(host)

            payload = self._generate_payload(extend_source="true", type="url", order_by="-created_ts", value__regexp=value_regexp, limit=limit)
        else:
            payload = self._generate_payload(extend_source="true", order_by="-created_ts", value=value, limit=limit)

        intel_details = self._paginator(ENDPOINT_INTELLIGENCE, action_result, payload=payload)

        if intel_details is None:
            return action_result.get_status()

        for detail in intel_details:
            action_result.add_data(detail)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved intel details")

    def _pdns(self, value, ioc_type, action_result):

        # Validate input
        if ioc_type not in [ "ip", "domain" ]:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_TYPE)

        payload = self._generate_payload(order_by="-last_seen")
        pdns = ENDPOINT_PDNS.format(ioc_type=ioc_type, ioc_value=value)

        ret_val, resp_json = self._make_rest_call(action_result, pdns, payload)
        if (phantom.is_fail(ret_val) or not resp_json["success"]):
            return action_result.get_status()

        # action_result.add_data({'pdns': resp_json['results']})
        # self._data_dict['pdns'] = resp_json['results']
        if action_result.get_data():
            action_result.add_data(action_result.get_data()[0].update({'pdns': resp_json['results']}))
        else:
            action_result.add_data({'pdns': resp_json['results']})
        return action_result.set_status(phantom.APP_SUCCESS, "Retrieved")

    def _insight(self, value, ioc_type, action_result):

        # Validate input
        if ioc_type not in [ "ip", "domain", "email", "md5", "sha1", "sha256" ]:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_TYPE)

        payload = self._generate_payload(type=ioc_type, value=value)

        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_INISGHT, payload)
        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, "Error retrieving insights")

        if action_result.get_data():
            action_result.add_data(action_result.get_data()[0].update({'insights': resp_json['insights']}))
        else:
            action_result.add_data({'insights': resp_json['insights']})
        return action_result.set_status(phantom.APP_SUCCESS, "Retrieved")

    def _external_references(self, value, action_result):

        payload = self._generate_payload()
        ext_ref = ENDPOINT_REFERENCE.format(ioc_value=value)

        ret_val, resp_json = self._make_rest_call(action_result, ext_ref, payload)

        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_SUCCESS, "Error retrieving external references")

        if action_result.get_data():
            action_result.add_data(action_result.get_data()[0].update({'external_references': resp_json}))
        else:
            action_result.add_data({'external_references': resp_json})
        return action_result.set_status(phantom.APP_SUCCESS, "Retrieved")

    def _whois(self, value, action_result, tipe=""):
        payload = self._generate_payload()
        whois = ENDPOINT_WHOIS.format(ioc_value=value)
        final_response = dict()

        ret_val, resp_json = self._make_rest_call(action_result, whois, payload)
        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, "Error making whois request")

        if not resp_json.get("data") or (resp_json['data'] == WHOIS_NO_DATA):
            return action_result.set_status(phantom.APP_ERROR, WHOIS_NO_DATA)

        try:
            whois_response = pythonwhois.parse.parse_raw_whois([resp_json['data']], True)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_FETCH_REPLY.format(error=str(e)))

        try:
            # Need to work on the json, it contains certain fields that are not
            # parsable, so will need to go the 'fallback' way.
            # TODO: Find a better way to do this
            whois_response = json.dumps(whois_response, default=_json_fallback)
            whois_response = json.loads(whois_response)
            final_response.update(whois_response)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_PARSE_REPLY.format(error=str(e)))

        try:
            if tipe == "ip":
                obj_whois = IPWhois(value)
                whois_response = obj_whois.lookup_whois(asn_methods=["whois", "dns", "http"])
                if whois_response:
                    final_response["addtional_info"] = whois_response
                else:
                    final_response["addtional_info"] = None
                    self.debug_print("The additional info response for the given IP is None")

                    action_result.add_data(final_response)
                    return action_result.set_status(phantom.APP_SUCCESS, "{}. {}".format(
                                THREATSTREAM_SUCCESS_WHOIS_MESSAGE, "Unable to fetch additional info for the given IP."))
        except Exception as e:
            final_response["addtional_info"] = None
            self.debug_print("Unable to fetch additional info for the given IP. ERROR: {error}".format(error=str(e)))

            action_result.add_data(final_response)
            return action_result.set_status(phantom.APP_SUCCESS, "{}. {}".format(
                        THREATSTREAM_SUCCESS_WHOIS_MESSAGE, "Unable to fetch additional info for the given IP. ERROR: {error}".format(error=str(e))))

        action_result.add_data(final_response)

        return action_result.set_status(phantom.APP_SUCCESS, THREATSTREAM_SUCCESS_WHOIS_MESSAGE)

    def _retrieve_ip_domain(self, value, ioc_type, action_result, limit=None):
        """ Retrieve all the information needed for domains or IPs """
        ret_val = self._intel_details(value, action_result, limit=limit)
        if (not ret_val):
            return action_result.get_status()

        ret_val = self._pdns(value, ioc_type, action_result)
        if (not ret_val):
            return action_result.get_status()

        ret_val = self._insight(value, ioc_type, action_result)
        if (not ret_val):
            return action_result.get_status()

        ret_val = self._external_references(value, action_result)
        if (not ret_val):
            return action_result.get_status()

        return phantom.APP_SUCCESS

    def _retrieve_email_md5(self, value, ioc_type, action_result, limit=None):
        """ Retrieve all the information needed for email or md5 hashes """

        ret_val = self._intel_details(value, action_result, limit=limit)
        if (not ret_val):
            return action_result.get_status()

        ret_val = self._insight(value, ioc_type, action_result)
        if (not ret_val):
            return action_result.get_status()

        ret_val = self._external_references(value, action_result)
        if (not ret_val):
            return action_result.get_status()

        return phantom.APP_SUCCESS

    def _test_connectivity(self, param):
        """ Test connectivity to threatstream by doing a simple request """
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Please verify if the hostname provided in the [hostname] parameter is cloud or on-prem and provide input \
                            in the [Is the provided instance in hostname parameter cloud?] parameter accordingly. \
                            This parameter will impact the actions' execution of the application.")

        self.save_progress("Starting connectivity test")
        payload = self._generate_payload(limit="1")
        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_INTELLIGENCE, payload)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Connectivity test failed")
            return action_result.get_status()

        self.save_progress("Connectivity test passed")
        return action_result.set_status(phantom.APP_SUCCESS, "")

    def _file_reputation(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        value = param[THREATSTREAM_JSON_HASH]

        try:
            limit = int(param.get("limit", 1000))
            if limit <= 0:
                return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="limit"))
        except:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="limit"))

        ioc_type = None

        if phantom.is_md5(value):
            ioc_type = "md5"
        if phantom.is_sha1(value):
            ioc_type = "sha1"
        if phantom.is_sha256(value):
            ioc_type = "sha256"

        ret_val = self._retrieve_email_md5(value, ioc_type, action_result, limit=limit)
        if (not ret_val):
            return action_result.get_status()
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved information on File")

    def _domain_reputation(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        value = UnicodeDammit(param[THREATSTREAM_JSON_DOMAIN]).unicode_markup.encode('utf-8')

        try:
            limit = int(param.get("limit", 1000))
            if limit <= 0:
                return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="limit"))
        except:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="limit"))

        if "/" in value:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_VALUE)

        ioc_type = "domain"
        ret_val = self._retrieve_ip_domain(value, ioc_type, action_result, limit=limit)
        if (not ret_val):
            return action_result.get_status()
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved information on Domain")

    def _ip_reputation(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        value = param[THREATSTREAM_JSON_IP]
        ioc_type = "ip"

        try:
            limit = int(param.get("limit", 1000))
            if limit <= 0:
                return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="limit"))
        except:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="limit"))

        ret_val = self._retrieve_ip_domain(value, ioc_type, action_result, limit=limit)
        if (not ret_val):
            return action_result.get_status()
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved information on IP")

    def _url_reputation(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        value = UnicodeDammit(param[THREATSTREAM_JSON_URL]).unicode_markup.encode("utf-8")

        try:
            limit = int(param.get("limit", 1000))
            if limit <= 0:
                return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="limit"))
        except:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="limit"))

        ret_val = self._intel_details(value, action_result, limit=limit)
        if (not ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved information on URL")

    def _email_reputation(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        value = UnicodeDammit(param[THREATSTREAM_JSON_EMAIL]).unicode_markup.encode("utf-8")
        ioc_type = "email"

        try:
            limit = int(param.get("limit", 1000))
            if limit <= 0:
                return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="limit"))
        except:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="limit"))

        ret_val = self._retrieve_email_md5(value, ioc_type, action_result, limit=limit)

        if (not ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved information on Email")

    def _whois_domain(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        value = UnicodeDammit(param[THREATSTREAM_JSON_DOMAIN]).unicode_markup.encode("utf-8")
        ret_val = self._whois(value, action_result, tipe="domain")
        if (not ret_val):
            return action_result.get_status()
        return action_result.get_status()

    def _whois_ip(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        value = param[THREATSTREAM_JSON_IP]
        ret_val = self._whois(value, action_result, tipe="ip")
        if (not ret_val):
            return action_result.get_status()
        return action_result.get_status()

    def _paginator(self, endpoint, action_result, payload=None, offset=0, limit=None):

        items_list = list()

        if payload:
            payload['limit'] = DEFAULT_MAX_RESULTS
        else:
            payload = self._generate_payload(limit=DEFAULT_MAX_RESULTS)

        payload['offset'] = offset

        while True:
            ret_val, items = self._make_rest_call(action_result, endpoint, payload)

            if phantom.is_fail(ret_val):
                return None

            items_list.extend(items.get("objects"))

            if limit and len(items_list) >= limit:
                return items_list[:limit]

            if len(items.get("objects")) < DEFAULT_MAX_RESULTS:
                break

            offset = offset + DEFAULT_MAX_RESULTS
            payload['offset'] = offset

        return items_list

    def _handle_list_observable(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            limit = int(param.get("limit", 1000))
            if limit <= 0:
                return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="limit"))
        except:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="limit"))

        payload = self._generate_payload()
        payload["order_by"] = "-created_ts"

        observable = self._paginator(ENDPOINT_INTELLIGENCE, action_result, limit=limit, payload=payload)

        if observable is None:
            return action_result.get_status()

        for obs in observable:
            action_result.add_data(obs)

        summary = action_result.update_summary({})
        summary['observables_returned'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_vulnerability(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            limit = int(param.get("limit", 1000))
            if limit <= 0:
                return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="limit"))
        except:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="limit"))

        payload = self._generate_payload(order_by="-created_ts")
        vulnerability = self._paginator(ENDPOINT_VULNERABILITY, action_result, payload=payload, limit=limit)

        if vulnerability is None:
            return action_result.get_status()

        for vul in vulnerability:
            action_result.add_data(vul)

        summary = action_result.update_summary({})
        summary['vulnerabilities_returned'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_incidents(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            limit = int(param.get("limit", 1000))
            if limit <= 0:
                return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="limit"))
        except:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="limit"))

        payload = self._generate_payload(order_by="-created_ts")

        if param.get("intel_value", None):
            payload["value"] = param["intel_value"]
            incidents = self._paginator(ENDPOINT_INCIDENT_WITH_VALUE, action_result, payload=payload, limit=limit)
        else:
            incidents = self._paginator(ENDPOINT_INCIDENT, action_result, payload=payload, limit=limit)

        if incidents is None:
            return action_result.get_status()

        list_incident_name = list()
        for incident in incidents:
            list_incident_name.append(incident.get("name"))
            action_result.add_data(incident)

        summary = action_result.update_summary({})
        summary['incidents_returned'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_incident_support(self, action_result, param=None, payload=None, incident_id=None):

        ret_val = None
        resp_json = None
        if payload and payload.get("remote_api") is not None:
            del payload["remote_api"]

        if not payload:
            payload = self._generate_payload()
        if param and param.get("incident_id"):
            try:
                incident_id = int(param["incident_id"])
            except ValueError:
                return action_result.set_status(phantom.APP_ERROR, "Please provide a valid interger in 'incident id' parameter"), None
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Error: {}".format(str(e))), None

        if self._is_cloud_instance:
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident_id), payload)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None
        else:
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident_id), payload)

            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident_id), payload)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            endpoint = "{}{}/".format(ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident_id), "intelligence")

            response = self._paginator(endpoint, action_result, payload=payload)

            if response is None:
                return action_result.get_status(), None

            resp_json.update({"intelligence": response})

        action_result.set_status(phantom.APP_SUCCESS, "")

        return phantom.APP_SUCCESS, resp_json

    def _handle_get_incident(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, resp_json = self._get_incident_support(action_result, param)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved incident")

    def _handle_get_observable(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            intelligence_id = int(param["intelligence_id"])
        except ValueError:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid interger in 'intelligence id' parameter")
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error: {}".format(str(e)))

        payload = self._generate_payload(id=intelligence_id)

        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_INTELLIGENCE, payload)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not resp_json.get("objects"):
            return action_result.set_status(phantom.APP_ERROR, "Please enter a valid 'intelligence id' parameter")

        action_result.add_data(resp_json.get("objects")[0])
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved observable")

    def _handle_get_vulnerability(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = None
        resp_json = None
        try:
            vulnerability_id = int(param["vulnerability_id"])
        except ValueError:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid interger in 'vulnerability id' parameter")
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error: {}".format(str(e)))

        payload = self._generate_payload()

        if self._is_cloud_instance:
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_VULNERABILITY.format(vul_id=vulnerability_id), payload)
        else:
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_VULNERABILITY.format(vul_id=vulnerability_id), payload)

            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_VULNERABILITY.format(vul_id=vulnerability_id), payload)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved vulnerability")

    def _handle_delete_incident(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            incident_id = int(param["incident_id"])
        except ValueError:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid interger in 'incident id' parameter")
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error: {}".format(str(e)))

        payload = self._generate_payload()

        if self._is_cloud_instance:
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident_id), payload, method="delete")
        else:
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident_id), payload, method="delete")

            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident_id), payload, method="delete")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted incident")

    def _handle_create_incident(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        create_on_cloud = param.get("create_on_cloud", False)

        data = {
                "name": param["name"], "is_public": param.get("is_public", False), "status": 1
               }
        data_dict = self._build_data(param, data, action_result)
        if data_dict is None:
            return action_result.get_status()

        data = data_dict.get("data")
        local_intelligence = data_dict.get("local_intelligence")
        cloud_intelligence = data_dict.get("cloud_intelligence")

        payload = self._generate_payload()
        final_creation = False
        intelligence = list()

        if self._is_cloud_instance:
            final_creation = True
            if cloud_intelligence:
                data.update({"intelligence": cloud_intelligence})
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_INCIDENT, payload, data=data, method="post")

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            for intel in resp_json.get("intelligence", []):
                intelligence.append(intel.get("id"))

        elif create_on_cloud:
            final_creation = True
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_INCIDENT, payload, data=data, method="post")

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            incident_id = resp_json.get("id")
            if not incident_id:
                return action_result.set_status(phantom.APP_ERROR, "Error while fetching the incident ID of the created incident on the cloud")

            if cloud_intelligence:
                intel_data = {"ids": cloud_intelligence}
                ret_val, response = self._make_rest_call(
                            action_result, ENDPOINT_ASSOCIATE_INTELLIGENCE.format(incident=incident_id), payload, data=intel_data, method="post")

                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                if response.get("ids"):
                    intelligence.extend(response.get("ids"))

            if local_intelligence:
                del payload["remote_api"]
                intel_data = {"local_ids": local_intelligence}
                ret_val, response = self._make_rest_call(
                            action_result, ENDPOINT_ASSOCIATE_INTELLIGENCE.format(incident=incident_id), payload, data=intel_data, method="post")

                if phantom.is_fail(ret_val):
                    self.debug_print("Error occurred while associating local IDs: {}. Please provide valid local IDs in 'local intelligence' parameter".format(
                        ', '.join(local_intelligence)))

                if response and response.get("local_ids"):
                    intelligence.extend(response.get("local_ids"))

        else:
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_INCIDENT, payload, data=data, method="post")

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            incident_id = resp_json.get("id")

            if not incident_id:
                return action_result.set_status(phantom.APP_ERROR, "Error while fetching the incident ID of the created incident on the on-prem")

            intel_data = dict()

            if local_intelligence:
                intel_data["ids"] = local_intelligence
            if cloud_intelligence:
                intel_data["remote_ids"] = cloud_intelligence

            if intel_data:
                ret_val, response = self._make_rest_call(
                            action_result, ENDPOINT_ASSOCIATE_INTELLIGENCE.format(incident=incident_id), payload, data=intel_data, method="post")

                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                if response.get("remote_ids"):
                    intelligence.extend(response.get("remote_ids"))

                if response.get("ids"):
                    intelligence.extend(response.get("ids"))

        intel_list = list()

        if intelligence:
            msg_intel = list()
            for i in intelligence:
                intel_id_dict = dict()
                intel_id_dict["id"] = i
                intel_list.append(intel_id_dict)
                msg_intel.append(str(i))

            resp_json["intelligence"] = intel_list

            message = "Incident created successfully. Associated intelligence : {}".format(', '.join(msg_intel))

        elif (local_intelligence or cloud_intelligence) and not intelligence:
            message = "Incident created successfully. None of the intelligence got associated, please provide valid intelligence"

        else:
            message = "Incident created successfully"

        action_result.add_data(resp_json)
        summary = action_result.update_summary({})
        summary['created_on_cloud'] = final_creation
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_update_incident(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = None
        resp_json = None
        message = None
        try:
            incident_id = int(param["incident_id"])
        except ValueError:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid interger in 'incident id' parameter")
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error: {}".format(str(e)))

        if not (param.get("local_intelligence") or param.get("cloud_intelligence")) and not param.get("fields"):
            return action_result.set_status(phantom.APP_ERROR, "Please provide at least one parameter, either 'intelligence' or 'fields' to update the provided incident")

        data = {}
        intel_ids_list = list()
        data_dict = self._build_data(param, data, action_result)
        if data_dict is None:
            return action_result.get_status()

        local_intelligence = data_dict.get("local_intelligence")
        cloud_intelligence = data_dict.get("cloud_intelligence")
        data = data_dict.get("data")

        payload = self._generate_payload()

        if self._is_cloud_instance:
            if cloud_intelligence:
                data.update({"intelligence": cloud_intelligence})
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident_id), payload, data=data, method="patch")
        else:

            if local_intelligence or cloud_intelligence:
                intel_data = dict()
                if local_intelligence:
                    intel_data["ids"] = local_intelligence

                if cloud_intelligence:
                    intel_data["remote_ids"] = cloud_intelligence

                ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_ASSOCIATE_INTELLIGENCE.format(incident=incident_id), payload, data=intel_data, method="post")

                if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                    intel_data = dict()
                    if local_intelligence:
                        intel_data["local_ids"] = local_intelligence

                        ret_val, resp_json = self._make_rest_call(
                            action_result, ENDPOINT_ASSOCIATE_INTELLIGENCE.format(incident=incident_id), payload, data=intel_data, method="post")

                        if phantom.is_fail(ret_val):
                            self.debug_print("Error occurred while associating local IDs: {}. Please provide valid local IDs in 'local intelligence' parameter".format(
                                ', '.join(local_intelligence)))
                        del intel_data["local_ids"]
                        if resp_json and resp_json.get("local_ids"):
                            intel_ids_list.extend(resp_json.get("local_ids"))

                    if cloud_intelligence:
                        intel_data["ids"] = cloud_intelligence
                        payload["remote_api"] = "true"
                        ret_val, resp_json = self._make_rest_call(
                            action_result, ENDPOINT_ASSOCIATE_INTELLIGENCE.format(incident=incident_id), payload, data=intel_data, method="post")

                        if phantom.is_fail(ret_val):
                            return action_result.get_status()

                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                if resp_json.get("ids"):
                    intel_ids_list.extend(resp_json.get("ids"))
                if resp_json.get("remote_ids"):
                    intel_ids_list.extend(resp_json.get("remote_ids"))

            if intel_ids_list:
                msg_intel = list()
                for i in intel_ids_list:
                    msg_intel.append(str(i))

                message = "Associated intelligence : {}".format(', '.join(msg_intel))

            elif (local_intelligence or cloud_intelligence) and not intel_ids_list:
                message = "None of the intelligence got associated, please provide valid intelligence"

            else:
                message = None

            associated_intelligence = data_dict.get("associated_intelligence")
            if associated_intelligence:
                intel_ids_list.extend(associated_intelligence)

            # Update the incident in all cases with data or with empty data to get the latest intelligence values associated with it
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident_id), payload, data=data, method="patch")

            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident_id), payload, data=data, method="patch")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        intel_list = list()

        intel_ids_list = list(set(intel_ids_list))

        if intel_ids_list:
            for i in intel_ids_list:
                intel_id_dict = dict()
                intel_id_dict["id"] = i
                intel_list.append(intel_id_dict)

            resp_json["intelligence"] = intel_list

        action_result.add_data(resp_json)
        if message:
            return action_result.set_status(phantom.APP_SUCCESS, "Successfully updated incident. {}".format(message))
        else:
            return action_result.set_status(phantom.APP_SUCCESS, "Successfully updated incident")

    def _build_data(self, param, data, action_result):

        if param.get("fields", None):
            try:
                fields = ast.literal_eval(param["fields"])
            except Exception as e:
                if e.message:
                    try:
                        error_msg = UnicodeDammit(e.message).unicode_markup.encode('utf-8')
                    except:
                        error_msg = "Unknown error occurred"
                else:
                    error_msg = "Unknown error occurred"
                action_result.set_status(phantom.APP_ERROR, "Error building fields dictionary: {0}. Please ensure that provided input is in valid JSON format.".format(error_msg))
                return None

            if not isinstance(fields, dict):
                action_result.set_status(phantom.APP_ERROR, "Error building fields dictionary. Please ensure that provided input is in valid JSON dictionary format")
                return None

            if fields.get("tags") and not isinstance(fields.get("tags"), list):
                action_result.set_status(phantom.APP_ERROR, "Please enter the value of the key, 'tags', in 'fields' parameter in form of list")
                return None

            data.update(fields)

        data_dict = dict()
        local_intelligence = param.get("local_intelligence")
        cloud_intelligence = param.get("cloud_intelligence")

        # 1. Fetch the existing intelligence values in the incident to append to
        # in case of cloud instance API because it overwrites the existing values
        associated_intell = list()

        if self.get_action_identifier() == 'update_incident':

            ret_val, resp_json = self._get_incident_support(action_result, param)

            if phantom.is_fail(ret_val):
                return None

            for intell in resp_json.get("intelligence", []):
                associated_intell.append(int(intell.get("id")))

        if local_intelligence:
            local_intelligence = self._create_intelligence(action_result, local_intelligence)
            if local_intelligence is None:
                return local_intelligence

        if cloud_intelligence:
            cloud_intelligence = self._create_intelligence(action_result, cloud_intelligence)
            if cloud_intelligence is None:
                return cloud_intelligence

        data_dict.update({"data": data, "local_intelligence": local_intelligence, "cloud_intelligence": cloud_intelligence, "associated_intelligence": associated_intell})

        return data_dict

    def _create_intelligence(self, action_result, intelligence):
        # Adding a first check if we have been supplied a list - this will
        # be useful for playbooks supplying a list object as the parameter

        if type(intelligence) is list:
            try:
                intel = [x.strip() for x in intelligence if x.strip() != '']
            except Exception as e:
                action_result.set_status(phantom.APP_ERROR, "Error building list of intelligence IDs: {0}. Please supply as comma separated string of integers".format(e))
                return None
        else:
            try:
                intel = intelligence.strip().split(",")
                intel = [x.strip() for x in intel if x.strip() != '']

            except Exception as e:
                action_result.set_status(phantom.APP_ERROR, "Error building list of intelligence IDs: {0}. Please supply as comma separated string of integers".format(e))
                return None
        return intel

    def _handle_run_query(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        payload = self._generate_payload()

        search_dict = {}

        try:
            # Check to see if the saved search parameter is filled out. This will take priority over a query
            if param.get("saved_search"):
                search_string = param.get("saved_search")
                search_dict = json.loads(json.dumps({'search_filter': search_string}))
            else:
                # Check to see if the type is based on JSON or the Anomali Filter Language query
                # If the query is an Anomali Filter Langauge query we need to add the q parameter. 
                # The q parameter also needs to be URL encoded, which Requests does for us.
                if param.get("query_type") == "AFL":
                    search_string = param.get("query")
                    search_dict = json.loads(json.dumps({'q': search_string}))
                elif param.get("query_type") == "JSON":
                    search_string = param.get("query")
                    search_dict = json.loads(search_string)
            payload.update(search_dict)
        except Exception as e:
            if e.message:
                try:
                    error_msg = UnicodeDammit(e.message).unicode_markup.encode('utf-8')
                except:
                    error_msg = "Unknown error occurred."
            else:
                error_msg = "Unknown error occurred."
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while parsing the JSON string provided in the 'query' parameter. Error: {0}".format(error_msg))

        order_by = param.get("order_by")
        if order_by:
            payload['order_by'] = order_by

        try:
            offset = param.get('offset', 0)
            if offset and (not str(offset).isdigit() or offset < 0):
                return action_result.set_status(phantom.APP_ERROR, "Please provide a positive integer in {param}".format(param="offset"))

            if offset == 0 or offset:
                offset = int(offset)
        except:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a positive integer in {param}".format(param="offset"))

        try:
            limit = int(param.get("limit", 1000))
            if limit <= 0:
                return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="limit"))
        except:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="limit"))

        records = self._paginator(ENDPOINT_INTELLIGENCE, action_result, payload=payload, offset=offset, limit=limit)

        if records is None:
            return action_result.get_status()

        for record in records:
            action_result.add_data(record)

        summary = action_result.update_summary({})
        summary['records_returned'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def import_support(self, param, action_result):

        payload = self._generate_payload()
        action_name = self.get_action_identifier()
        create_on_cloud = param.get("create_on_cloud", False)
        final_creation = False

        if self._is_cloud_instance or create_on_cloud:
            final_creation = True
            payload["remote_api"] = "true"

        if action_name == self.ACTION_ID_IMPORT_IOC:
            if param["observable_type"] == "ip":
                ob_type = "srcip"
            elif param["observable_type"] == "hash":
                ob_type = "md5"
            else:
                ob_type = param["observable_type"]

            value = param["value"]

            data = {
                    "objects": [
                        {ob_type: value, "classification": param["classification"]}
                    ]
                }

            if param.get("fields", None):
                try:
                    fields = ast.literal_eval(param["fields"])
                except Exception as e:
                    if e.message:
                        try:
                            error_msg = UnicodeDammit(e.message).unicode_markup.encode('utf-8')
                        except:
                            error_msg = "Unknown error occurred"
                    else:
                        error_msg = "Unknown error occurred"
                    return action_result.set_status(phantom.APP_ERROR, "Error building fields dictionary: {0}. \
                        Please ensure that provided input is in valid JSON format".format(error_msg))

                if "itype" in fields:
                    data["objects"][0].update(fields)
                else:
                    return action_result.set_status(phantom.APP_ERROR, "Providing 'itype' in fields parameter is mandatory for importing an observable \
                    (e.g. {\"itype\": \"<indicator_type>\"})")
                #        , "itype": "actor_ip", "detail": "dionea,smbd,port-445,Windows-XP,DSL", "confidence": 50, "severity": "high"}
            else:
                return action_result.set_status(phantom.APP_ERROR, "Providing 'itype' in fields parameter is mandatory for importing an observable \
                (e.g. {\"itype\": \"<indicator_type>\"})")
        else:
            indicator_type = param['indicator_type']
            confidence = param.get('confidence', None)
            classification = param.get('classification')
            severity = param.get('severity')
            tags = param.get('tags')

            if (confidence and confidence < 0) or (confidence and (not str(confidence).isdigit() or confidence <= 0)):
                return action_result.set_status(phantom.APP_ERROR, THREARSTREAM_INVALID_CONFIDENCE)

            if confidence:
                confidence = int(confidence)

            object_dict = {"itype": indicator_type}

            if action_name == self.ACTION_ID_IMPORT_EMAIL_OBSERVABLES:
                value = param['email']
                object_dict.update({"email": value})

            if action_name == self.ACTION_ID_IMPORT_FILE_OBSERVABLES:
                value = param['file_hash']
                object_dict.update({"md5": value})

            if action_name == self.ACTION_ID_IMPORT_IP_OBSERVABLES:
                value = param['ip_address']
                object_dict.update({"srcip": value})

            if action_name == self.ACTION_ID_IMPORT_URL_OBSERVABLES:
                value = param['url']
                object_dict.update({"url": value})

            if action_name == self.ACTION_ID_IMPORT_DOMAIN_OBSERVABLES:
                value = param['domain']
                object_dict.update({"domain": value})

            if confidence:
                object_dict.update({"confidence": confidence})

            if severity:
                object_dict.update({"severity": severity})

            if classification:
                object_dict.update({"classification": classification})

            if tags:
                tag = [x.strip() for x in tags.split(',')]
                tag = list(filter(None, tag))
                object_dict.update({"tags": tag})

            data = {
                    "objects": [
                        object_dict
                    ]
                }

        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_IMPORT_IOC, payload=payload, data=data, method="patch")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        summary = action_result.update_summary({})
        summary['created_on_cloud'] = final_creation

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully sent the request for importing the observable")

    def _handle_import_email_observable(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.import_support(param, action_result)
        return action_result.get_status()

    def _handle_import_file_observable(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.import_support(param, action_result)
        return action_result.get_status()

    def _handle_import_ip_observable(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.import_support(param, action_result)
        return action_result.get_status()

    def _handle_import_url_observable(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.import_support(param, action_result)
        return action_result.get_status()

    def _handle_import_domain_observable(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.import_support(param, action_result)
        return action_result.get_status()

    def _handle_import_ioc(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.import_support(param, action_result)
        return action_result.get_status()

    def _handle_tag_ioc(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        config = self.get_config()
        try:
            intelligence_id = int(param["id"])
        except ValueError:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid interger in 'intelligence id' parameter")
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error: {}".format(str(e)))

        org_id = config.get("organization_id", None)
        if org_id is None:
            return action_result.set_status(phantom.APP_ERROR, "Please set the organization ID config value prior to tagging an observable")

        payload = self._generate_payload()

        # tags should be a comma-separated list
        tags = [x.strip() for x in param[THREATSTREAM_JSON_TAGS].split(',')]
        tags = list(filter(None, tags))
        data = {THREATSTREAM_JSON_TAGS: []}

        for tag in tags:
            data[THREATSTREAM_JSON_TAGS].append({
                "name": tag,
                "org_id": org_id,
                "tlp": param.get('tlp', 'red'),
                THREATSTREAM_JSON_SOURCE_USER_ID: param[THREATSTREAM_JSON_SOURCE_USER_ID]
            })

        endpoint = ENDPOINT_TAG_IOC.format(indicator_id=intelligence_id)

        if self._is_cloud_instance:
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, data=data, method="post")
        else:
            ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, data=data, method="post")

            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, data=data, method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully tagged observable")

    def _handle_get_status(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        payload = self._generate_payload()
        endpoint = UnicodeDammit(param.get("endpoint")).unicode_markup.encode('utf-8')
        endpoint = endpoint.replace("/api/", "/")
        ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, method="get")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()
        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved detonation status")

    def _handle_get_report(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        payload = self._generate_payload()
        endpoint = param.get("endpoint")
        if "report" not in endpoint:
            return action_result.set_status(phantom.APP_ERROR, "Please provide correct report endpoint")

        endpoint = endpoint.replace("/api/", "/")
        ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, method="get")
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()
        action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved detonation report")

    def _handle_detonate_file(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        # return action_result.set_status(phantom.APP_SUCCESS, param.get('classification'))
        vault_id = UnicodeDammit(param.get('vault_id')).unicode_markup.encode('utf-8')

        try:
            vault_info = Vault.get_file_info(vault_id=vault_id)
        except Exception as e:
            if e.message:
                try:
                    error_msg = UnicodeDammit(e.message).unicode_markup.encode('utf-8')
                except:
                    error_msg = "Unknown error occurred."
            else:
                error_msg = "Unknown error occurred."
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching the file info. Error: {}".format(error_msg))

        if not vault_info:
            return action_result.set_status(phantom.APP_ERROR, "Error while fetching the vault information of the vault id: '{}'".format(param.get('vault_id')))

        for item in vault_info:
            vault_path = item.get('path')
            if vault_path is None:
                return action_result.set_status(phantom.APP_ERROR, "Could not find a path associated with the provided vault ID")
            try:
                vault_file = open(vault_path)
            except Exception as e:
                if e.message:
                    try:
                        error_msg = UnicodeDammit(e.message).unicode_markup.encode('utf-8')
                    except:
                        error_msg = "Unknown error occurred."
                else:
                    error_msg = "Unknown error occurred."
                return action_result.set_status(phantom.APP_ERROR, "Unable to open vault file: {}".format(error_msg))

            payload = self._generate_payload()

            files = {
                "file": vault_file
            }
            data = {
                "report_radio-platform": param.get('platform', 'ALL'),
                "report_radio-file": vault_path,
                "report_radio-classification": param.get('classification')
            }

            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_FILE_DETONATION, payload, data=data, method="post", files=files, use_json=False)
            if (phantom.is_fail(ret_val)):
                return action_result.get_status()
            action_result.add_data(resp_json)
            return action_result.set_status(phantom.APP_SUCCESS, "Successfully detonated file")

    def _handle_detonate_url(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        payload = self._generate_payload()
        data = {
            "report_radio-platform": param.get('platform', 'ALL'),
            "report_radio-url": param.get('url'),
            "report_radio-classification": param.get('classification')
        }

        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_URL_DETONATION, payload, data=data, method="post", use_json=False)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()
        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully detonated URL")

    def _handle_get_pcap(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        payload = self._generate_payload()
        if param and param.get("id"):
            try:
                report_id = int(param["id"])
            except ValueError:
                return action_result.set_status(phantom.APP_ERROR, "Please provide a valid interger in 'id' parameter")
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Error: {}".format(str(e)))

        endpoint = ENDPOINT_GET_REPORT.format(report_id=report_id)

        # retrieve report data
        ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        ret_val, vault_details = self._save_pcap_to_vault(resp_json, self.get_container_id(), action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(vault_details)

        return action_result.set_status(phantom.APP_SUCCESS, "PCAP file added successfully to the vault")

    def _save_pcap_to_vault(self, response, container_id, action_result):
        # get URL to pcap file
        try:
            pcap = response['pcap']
        except KeyError:
            return action_result.set_status(phantom.APP_ERROR, "Could not find PCAP file to download from report"), None

        filename = os.path.basename(urlsplit(pcap).path)

        # download file
        try:
            pcap_file = requests.get(pcap).content
        except:
            return action_result.set_status(phantom.APP_ERROR, "Could not download PCAP file"), None

        # Creating temporary directory and file
        try:
            if hasattr(Vault, 'get_vault_tmp_dir'):
                temp_dir = Vault.get_vault_tmp_dir()
            else:
                temp_dir = "/opt/phantom/vault/tmp/"
            temp_dir = temp_dir + '/{}'.format(uuid.uuid4())
            os.makedirs(temp_dir)
            file_path = os.path.join(temp_dir, filename)

            with open(file_path, 'wb') as file_obj:
                file_obj.write(pcap_file)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error while writing to temporary file", e), None

        # Adding pcap to vault
        vault_ret_dict = Vault.add_attachment(file_path, container_id, filename)

        # Removing temporary directory created to download file
        try:
            shutil.rmtree(temp_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to remove temporary directory", e), None

        # Updating data with vault details
        if vault_ret_dict['succeeded']:
            vault_details = {
                phantom.APP_JSON_VAULT_ID: vault_ret_dict[phantom.APP_JSON_HASH],
                'file_name': filename
            }
            return phantom.APP_SUCCESS, vault_details

        # Error while adding report to vault
        self.debug_print('Error adding file to vault:', vault_ret_dict)
        action_result.append_to_message('. {}'.format(vault_ret_dict['message']))

        # Set the action_result status to error, the handler function will most probably return as is
        return phantom.APP_ERROR, None

    def _check_and_update_container_already_exists(self, incident_id, incident_name):

        url = '{0}rest/container?_filter_source_data_identifier="{1}"&_filter_asset={2}'.format(self.get_phantom_base_url(), incident_id, self.get_asset_id())

        try:
            r = requests.get(url, verify=False)
            resp_json = r.json()
        except Exception as e:
            if e.message:
                try:
                    error_msg = UnicodeDammit(e.message).unicode_markup.encode('utf-8')
                except:
                    error_msg = "Unknown error occurred."
            else:
                error_msg = "Unknown error occurred."
            self.debug_print("Unable to query ThreatStream incident container: {}".format(error_msg))
            return None

        if (resp_json.get('count', 0) <= 0):
            self.debug_print("No container matched")
            return None

        try:
            container_id = resp_json.get('data', [])[0]['id']
        except Exception as e:
            self.debug_print("Container results are not proper: ", e)
            return None

        # If the container exists and the name of the incident has been updated,
        # update the name of the container as well to stay in sync with the UI of ThreatStream
        if container_id and (resp_json.get('data', [])[0]['name'] != '{}-{}'.format(incident_id, incident_name)):
            url = '{0}rest/container/{1}'.format(self.get_phantom_base_url(), container_id)
            try:
                data = {"name": '{}-{}'.format(incident_id, incident_name)}
                r = requests.post(url, verify=False, json=data)
                resp_json = r.json()
            except Exception as e:
                if e.message:
                    try:
                        error_msg = UnicodeDammit(e.message).unicode_markup.encode('utf-8')
                    except:
                        error_msg = "Unknown error occurred."
                else:
                    error_msg = "Unknown error occurred."
                self.debug_print("Unable to update the name of the ThreatStream incident container: {}".format(error_msg))
                return container_id

            if not resp_json.get('success'):
                self.debug_print("Container with ID: {0} could not be updated with the current incident_name: {1} of the incident ID: {2}".format(
                                    container_id, incident_name, incident_id))
                self.debug_print("Response of the container updation is: {0}".format(str(resp_json)))
                return container_id

        return container_id

    def _handle_on_poll(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        config = self.get_config()

        org_id = config.get("organization_id")
        if org_id is None:
            return action_result.set_status(phantom.APP_ERROR, "Please set the organization ID config value before polling")

        self.save_progress("Retrieving incidents...")

        try:
            # Fetch the last fetched incident's ID in case of subsequent
            # polls for the scheduled polling
            start_ingestion_time = None

            if not self.is_poll_now() and self._state.get("first_run") is False:
                start_ingestion_time = self._state.get("last_incident_time")
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching the incident ID of the last ingestion run. Error: {0}".format(str(e)))

        try:
            if self.is_poll_now():
                # Manual polling
                limit = param.get("container_count", 1000)
                parameter = "container_count"
            elif self._state.get("first_run", True):
                # Scheduled polling first run
                limit = self._first_run_limit
                self._state["first_run"] = False
                parameter = "first_run_containers"
            else:
                # Poll every new update in the subsequent polls
                # of the scheduled_polling
                limit = None

            try:
                if limit == 0 or (limit and (not str(limit).isdigit() or limit <= 0)):
                    return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param=parameter))

                if limit:
                    limit = int(limit)
            except:
                return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param=parameter))

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching the number of containers to be ingested. Error: {0}".format(str(e)))

        if start_ingestion_time:
            payload = self._generate_payload(order_by="modified_ts", modified_ts__gte=start_ingestion_time)
        else:
            payload = self._generate_payload(order_by="modified_ts")

        incidents = []
        if limit:
            offset = 0
            while len(incidents) < limit:
                interim_incidents = self._paginator(ENDPOINT_INCIDENT, action_result, payload=payload, offset=offset, limit=DEFAULT_MAX_RESULTS)

                if interim_incidents is None:
                    return action_result.get_status()

                for incident in interim_incidents:
                    if incident.get("organization_id") == int(org_id):
                        incidents.append(incident)
                    else:
                        self.debug_print("Skipping incident ID: {0} due to organization ID: {1} being different than the configuration parameter organization_id: {2}".format(
                                    incident.get("id"), incident.get("organization_id"), org_id))

                if not interim_incidents:
                    break

                offset += DEFAULT_MAX_RESULTS

            # Fetch only the incidents equal to the number denoted by limit
            incidents = incidents[:limit]
        else:
            interim_incidents = self._paginator(ENDPOINT_INCIDENT, action_result, payload=payload, limit=limit)

            if interim_incidents is None:
                return action_result.get_status()

            for incident in interim_incidents:
                if incident.get("organization_id") == int(org_id):
                    incidents.append(incident)
                else:
                    self.debug_print("Skipping incident ID: {0} due organization ID: {1} being different than the configuration parameter organization_id: {2}".format(
                                incident.get("id"), incident.get("organization_id"), org_id))

        self.save_progress("Fetched {0} incidents in the oldest first order based on modified_ts time.".format(len(incidents)))
        self.save_progress("Started incident and intelligence artifacts creation...")

        for i, incident in enumerate(incidents):
            self.send_progress("Processing incident and corresponding intelligence artifacts - {} %".format(((i + 1) / len(incidents)) * 100))
            # self.send_progress("Processing containers and artifacts creation for the incident ID: {0}".format(incident.get("id")))
            # Handle the ingest_only_published_incidents scenario
            if config.get("ingest_only_published_incidents"):
                if "published" != incident.get("publication_status"):
                    self.debug_print("Skipping incident ID: {0} because ingest_only_published_incidents configuration parameter is marked true".format(incident.get("id")))
                    continue

            self.debug_print("Retrieving details for the incident ID: {0}".format(incident.get("id")))

            ret_val, resp_json = self._get_incident_support(action_result, incident_id=incident["id"])

            if (not ret_val):
                return action_result.get_status()

            # Create the list of artifacts to be created
            artifacts_list = []
            intelligence = resp_json.pop("intelligence", [])

            for item in intelligence:
                artifact = {"label": "artifact",
                            "type": "network",
                            "name": "intelligence artifact",
                            "description": "Artifact added by ThreatStream App",
                            "source_data_identifier": item["id"]
                            }
                if item.get('tags'):
                    tags_dict = dict()
                    tags = item.get('tags')

                    for i, tag in enumerate(tags):
                        tags_dict['tag_{}'.format(i + 1)] = '    ||    '.join('{} : {}'.format(
                            key, UnicodeDammit(value).unicode_markup.encode('utf-8') if isinstance(value, basestring) else value) for key, value in tag.items())

                    item['tags_formatted'] = tags_dict

                artifact['cef'] = item
                artifact['cef_types'] = {'id': [ "threatstream intelligence id" ],
                        'owner_organization_id': [ "threatstream organization id" ],
                        'ip': [ "ip" ],
                        'value': [ "ip", "domain", "url", "email", "md5", "sha1", "hash" ]
                                }
                artifacts_list.append(artifact)

            artifact = {"label": "artifact",
                        "type": "network",
                        "name": "incident artifact",
                        "description": "Artifact added by ThreatStream App",
                        "source_data_identifier": resp_json["id"]
                        }

            if resp_json.get('tags_v2'):
                tags_dict = dict()
                tags = resp_json.get('tags_v2')

                for i, tag in enumerate(tags):
                    tags_dict['tag_v2_{}'.format(i + 1)] = '    ||    '.join('{} : {}'.format(
                        key, UnicodeDammit(value).unicode_markup.encode('utf-8') if isinstance(value, basestring) else value) for key, value in tag.items())

                resp_json['tags_v2_formatted'] = tags_dict

            artifact['cef'] = resp_json
            artifact['cef_types'] = {'id': [ "threatstream incident id" ], 'organization_id': [ "threatstream organization id" ]}
            artifacts_list.append(artifact)

            existing_container_id = self._check_and_update_container_already_exists(resp_json.get("id"), UnicodeDammit(resp_json.get("name")).unicode_markup.encode('utf-8'))

            self.debug_print("Saving container and adding artifacts for the incident ID: {0}".format(resp_json.get("id")))

            if not existing_container_id:
                container = dict()
                container['description'] = "Container added by ThreatStream app"
                container['source_data_identifier'] = resp_json.get("id")
                container['name'] = '{}-{}'.format(resp_json.get("id"), UnicodeDammit(resp_json.get("name")).unicode_markup.encode('utf-8'))
                container['data'] = resp_json

                ret_val, message, container_id = self.save_container(container)

                if (phantom.is_fail(ret_val)):
                    message = "Failed to add container error msg: {0}".format(message)
                    self.debug_print(message)
                    return action_result.set_status(phantom.APP_ERROR, "Failed creating container")

                if (not container_id):
                    message = "save_container did not return a container_id"
                    self.debug_print(message)
                    return action_result.set_status(phantom.APP_ERROR, "Failed creating container")

                existing_container_id = container_id

            # Add the artifacts_list to either the created or
            # the existing container with ID in existing_container_id
            for artifact in artifacts_list:
                artifact['container_id'] = existing_container_id

            ret_val, message, _ = self.save_artifacts(artifacts_list)

            if (not ret_val):
                self.debug_print("Error while saving the artifact for the incident ID: {0}".format(resp_json.get("id")), message)
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while saving the artifact for the incident ID: {0}. Error message: {1}".format(
                                                    resp_json.get("id"), message))

        if not self.is_poll_now() and incidents:
            # 2019-08-14T11:37:01.113736 to 2019-08-14T11:37:01 conversion
            # The incidents are sorted in the ascending order
            last_incident_time = incidents[-1].get("modified_ts")
            if last_incident_time:
                self._state["last_incident_time"] = last_incident_time

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved and ingested the list of incidents")

    def handle_action(self, param):

        action = self.get_action_identifier()
        ret_val = phantom.APP_SUCCESS

        if (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)
        elif (action == self.ACTION_ID_FILE_REPUTATION):
            ret_val = self._file_reputation(param)
        elif (action == self.ACTION_ID_DOMAIN_REPUTATION):
            ret_val = self._domain_reputation(param)
        elif (action == self.ACTION_ID_IP_REPUTATION):
            ret_val = self._ip_reputation(param)
        elif (action == self.ACTION_ID_URL_REPUTATION):
            ret_val = self._url_reputation(param)
        elif (action == self.ACTION_ID_EMAIL_REPUTATION):
            ret_val = self._email_reputation(param)
        elif (action == self.ACTION_ID_WHOIS_DOMAIN):
            ret_val = self._whois_domain(param)
        elif (action == self.ACTION_ID_WHOIS_IP):
            ret_val = self._whois_ip(param)
        elif (action == self.ACTION_ID_LIST_INCIDENTS):
            ret_val = self._handle_list_incidents(param)
        elif (action == self.ACTION_ID_LIST_VULNERABILITY):
            ret_val = self._handle_list_vulnerability(param)
        elif (action == self.ACTION_ID_LIST_OBSERVABLE):
            ret_val = self._handle_list_observable(param)
        elif (action == self.ACTION_ID_GET_INCIDENT):
            ret_val = self._handle_get_incident(param)
        elif (action == self.ACTION_ID_GET_VULNERABILITY):
            ret_val = self._handle_get_vulnerability(param)
        elif (action == self.ACTION_ID_GET_OBSERVABLE):
            ret_val = self._handle_get_observable(param)
        elif (action == self.ACTION_ID_DELETE_INCIDENT):
            ret_val = self._handle_delete_incident(param)
        elif (action == self.ACTION_ID_CREATE_INCIDENT):
            ret_val = self._handle_create_incident(param)
        elif (action == self.ACTION_ID_UPDATE_INCIDENT):
            ret_val = self._handle_update_incident(param)
        elif (action == self.ACTION_ID_IMPORT_IOC):
            ret_val = self._handle_import_ioc(param)
        elif (action == self.ACTION_ID_IMPORT_EMAIL_OBSERVABLES):
            ret_val = self._handle_import_email_observable(param)
        elif (action == self.ACTION_ID_IMPORT_FILE_OBSERVABLES):
            ret_val = self._handle_import_file_observable(param)
        elif (action == self.ACTION_ID_IMPORT_IP_OBSERVABLES):
            ret_val = self._handle_import_ip_observable(param)
        elif (action == self.ACTION_ID_IMPORT_URL_OBSERVABLES):
            ret_val = self._handle_import_url_observable(param)
        elif (action == self.ACTION_ID_IMPORT_DOMAIN_OBSERVABLES):
            ret_val = self._handle_import_domain_observable(param)
        elif (action == self.ACTION_ID_RUN_QUERY):
            ret_val = self._handle_run_query(param)
        elif (action == self.ACTION_ID_ON_POLL):
            ret_val = self._handle_on_poll(param)
        elif (action == self.ACTION_ID_DETONATE_FILE):
            ret_val = self._handle_detonate_file(param)
        elif (action == self.ACTION_ID_GET_STATUS):
            ret_val = self._handle_get_status(param)
        elif (action == self.ACTION_ID_GET_REPORT):
            ret_val = self._handle_get_report(param)
        elif (action == self.ACTION_ID_DETONATE_URL):
            ret_val = self._handle_detonate_url(param)
        elif (action == self.ACTION_ID_GET_PCAP):
            ret_val = self._handle_get_pcap(param)
        elif (action == self.ACTION_ID_TAG_IOC):
            ret_val = self._handle_tag_ioc(param)

        return ret_val


if __name__ == '__main__':

    # Imports
    import sys
    import pudb

    # Breakpoint at runtime
    pudb.set_trace()

    # The first param is the input json file
    with open(sys.argv[1]) as f:

        # Load the input json file
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        # Create the connector class object
        connector = ThreatstreamConnector()

        # Se the member vars
        connector.print_progress_message = True

        # Call BaseConnector::_handle_action(...) to kickoff action handling.
        ret_val = connector._handle_action(json.dumps(in_json), None)

        # Dump the return value
        print ret_val

    exit(0)
