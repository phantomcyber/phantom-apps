# File: domaintools_connector.py
# Copyright (c) 2016-2018 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

# Phantom App imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Imports local to this App

import json
from datetime import datetime
import hmac
import hashlib

import requests
import ipaddress


# Define the App Class
class DomainToolsConnector(BaseConnector):
    ACTION_ID_WHOIS_IP = "whois_ip"
    ACTION_ID_WHOIS_DOMAIN = "whois_domain"
    ACTION_ID_DOMAIN_PROFILE = "domain_profile"
    ACTION_ID_DOMAIN_SUGGEST = "domain_suggestions"
    ACTION_ID_WHOIS_HISTORY = "whois_history"
    ACTION_ID_HOSTING_HISTORY = "hosting_history"
    ACTION_ID_REVERSE_WHOIS = "reverse_whois"
    ACTION_ID_REVERSE_IPWHOIS = "reverse_ip_whois"
    ACTION_ID_REVERSE_IP = "reverse_lookup_ip"
    ACTION_ID_REVERSE_DOMAIN = "reverse_lookup_domain"
    ACTION_ID_REVERSE_NS = "reverse_name_server"
    ACTION_ID_DOMAIN_SEARCH = "domain_search"
    ACTION_ID_BRAND_MONITOR = "brand_monitor"
    ACTION_ID_REG_MONITOR = "registrant_monitor"
    ACTION_ID_NS_MONITOR = "name_server_monitor"
    ACTION_ID_IP_MONITOR = "ip_monitor"
    ACTION_ID_IP_REG_MONITOR = "ip_registrant_monitor"
    ACTION_ID_REVERSE_EMAIL = "reverse_whois_email"
    ACTION_ID_DOMAIN_REPUTATION = "domain_reputation"

    DOMAIN_KEY = 'domain'
    QUERY_KEY = 'query'
    IP_KEY = 'ip'
    HISTORY_ITEMS = "record_count"
    REGISTRAR_HIST = "registrar_history_count"
    IP_HIST = "ip_history_count"
    NS_HIST = "nameserver_history_count"
    IPS_COUNT = "total_ips"
    DOMAINS_COUNT = "total_domains"

    DOMAINTOOLS = 'api.domaintools.com'
    API_VERSION = 'v1'

    MSG_SET_CORRECT_TIME = "\r\nPlease make sure the system time is correct."
    MSG_SET_CORRECT_TIME += "\r\nDomainTools credentials validation might fail in case the time is misconfigured"

    def __init__(self):

        # Call the BaseConnectors init first
        super(DomainToolsConnector, self).__init__()

        self._username = None
        self._key = None

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

    def initialize(self):
        # get the app version
        self.app_version_number = self.get_app_json().get('app_version', '')
        self.set_validator('ipv6', self._is_ip)
        return phantom.APP_SUCCESS

    def _clean_empty_response(self, response):
        # PAPP-2087 DomainTools - Reverse Email table widget shows contextual action for no domain
        if response.get('domains') == []:
            del response['domains']
        #

    def _parse_response(self, action_result, r, response_json, ignore400=False):
        """
        No need to do exception handling, since this function call has a try...except around it.
        If you do want to catch a specific exception to generate proper error strings, go ahead
        """

        status = r.status_code
        response = response_json.get('response')
        error = response_json.get('error', {})

        if (status == 404) or (
                        (status == 400) and (ignore400) and (error.get('message', '').startswith('No IP addresses'))):
            action_result.add_data({})
            return action_result.set_status(phantom.APP_SUCCESS,
                                            error.get('message', 'Domain Tools failed to find IP/Domain'))

        if (status == 200) and (response):
            self._clean_empty_response(response)
            action_result.add_data(response)
            return action_result.set_status(phantom.APP_SUCCESS)

        return action_result.set_status(phantom.APP_ERROR,
                                        error.get('message', 'An unknown error occurred while querying domaintools.'))

    def _do_query(self, domain, endpoint, action_result, data=None, ignore400=False):
        if data is None:
            data = dict()

        full_endpoint = '/{}/{}/{}/'.format(self.API_VERSION, domain, endpoint)
        url = 'https://{}{}'.format(self.DOMAINTOOLS, full_endpoint)

        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

        sig_message = self._username + timestamp + full_endpoint

        sig = hmac.new(str(self._key), str(sig_message), digestmod=hashlib.sha1)

        data['api_username'] = self._username
        data['timestamp'] = timestamp
        data['signature'] = sig.hexdigest()
        data['app_name'] = 'domaintools_connector'
        data['app_version'] = self.app_version_number
        data['app_partner'] = 'PhantomCyber'

        self.save_progress("Connecting to domaintools")

        try:
            r = requests.post(url, data=data)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "REST API failed", e)

        self.save_progress("Parsing response")

        try:
            response_json = r.json()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse response as a valid JSON", e)

        self.debug_print(r.url)

        # Now parse and add the response into the action result
        try:
            return self._parse_response(action_result, r, response_json, ignore400=ignore400)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, 'An error occurred while parsing domaintools reponse', e)

        return phantom.APP_SUCCESS

    def _test_connectivity(self, param):

        domain = "phantomcyber.com"

        self.save_progress("Performing test query")

        # Progress
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, 'domaintools.com')

        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            self._parsed_whois_domain(domain, action_result)
            if action_result.get_status() != phantom.APP_SUCCESS:
                raise Exception(action_result.get_message())
        except Exception as e:
            message = 'Failed to connect to domaintools.com'
            self.set_status(phantom.APP_ERROR, message, e)
            self.append_to_message(self.MSG_SET_CORRECT_TIME)
            return self.get_status()

        return self.set_status_save_progress(phantom.APP_SUCCESS,
                                             'Successfully connected to domaintools.com.\nTest Connectivity passed')

    def _handle_response(self, http_response, action_result):

        try:
            response_json = http_response.json()
            status = http_response.status_code
            response = response_json.get('response')
            error = response_json.get('error', {})
            if status == 200:
                if response:
                    action_result.add_data(response)
                    action_result.set_status(phantom.APP_SUCCESS)
                else:
                    action_result.add_data(http_response.text)
                    action_result.set_status(phantom.APP_ERROR)
            else:
                action_result.add_data(http_response.text)
                action_result.set_status(phantom.APP_ERROR,
                                         error.get('message', 'An unknown error occurred while querying domaintools.'))
        except Exception as e:
            action_result.add_data(str(e))
            action_result.set_status(phantom.APP_ERROR, 'An error occurred while querying domaintools', e)

    def _parsed_whois_domain(self, domain, action_result):
        return self._do_query(domain, 'whois/parsed', action_result)

    def _regular_whois_domain(self, domain, action_result):
        return self._do_query(domain, 'whois', action_result)

    def _do_generic_action(self, param, endpoint):

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        if self.DOMAIN_KEY not in param and self.IP_KEY in param:
            param[self.DOMAIN_KEY] = param[self.IP_KEY]
            del param[self.IP_KEY]

        self.debug_print("param", param)
        self.debug_print("endpoint", endpoint)

        domain = param[self.DOMAIN_KEY]

        return self._do_query(domain, endpoint, action_result)

    def _domain_reputation(self, param):

        action_result = self.add_action_result(ActionResult(param))

        domain_to_query = param['domain']

        params = {'domain': domain_to_query}

        if param.get('use_risk_api'):
            ret_val = self._do_query('risk/evidence', '', action_result, data=params)
        else:
            ret_val = self._do_query('reputation', '', action_result, data=params)

        if not ret_val:
            return action_result.get_data()

        data = action_result.get_data()

        if not data:
            return action_result.get_status()

        action_result.update_summary({'risk_score': data[0].get('risk_score', None)})

        return action_result.get_status()

    def _handle_reverse_whois_email(self, param):

        action_result = self.add_action_result(ActionResult(param))

        email_to_query = param['email']

        params = {'terms': email_to_query,
                  'mode': 'quote' if param['count_only'] else 'purchase',
                  'scope': 'historic' if param['include_history'] else 'current'}

        ret_val = self._do_query('reverse-whois', '', action_result, data=params)

        if not ret_val:
            return action_result.get_data()

        data = action_result.get_data()

        if not data:
            return action_result.get_status()

        # set the summary
        try:
            action_result.update_summary({self.DOMAINS_COUNT: len(data[0]['domains'])})
        except:
            action_result.update_summary({self.DOMAINS_COUNT: 0})

        return action_result.get_status()

    def _brand_monitor(self, param):

        self.debug_print("param", param)

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        if ('status' in param):
            param['domain_status'] = param['status']

        ret_val = self._do_query('mark-alert', '', action_result, data=param)

        if (not ret_val):
            return action_result.get_data()

        data = action_result.get_data()

        if (not data):
            return action_result.get_status()

        # set the summary
        try:
            action_result.update_summary({self.DOMAINS_COUNT: len(data[0]['alerts'])})
        except:
            action_result.update_summary({self.DOMAINS_COUNT: 0})

        return action_result.get_status()

    def _reg_monitor(self, param):

        self.debug_print("param", param)

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        term = param[self.QUERY_KEY]
        params = {'query': '|'.join(term.split())}
        exclude = param.get('exclude')
        if exclude:
            params['exclude'] = '|'.join(exclude.split())
        days_back = param.get('days_back')
        if days_back and days_back.isdigit():
            params['days_back'] = int(days_back)
        limit = int(param.get('limit', 0))
        if limit:
            params['limit'] = limit

        return self._do_query('registrant-alert', '', action_result, data=params)

    def _whois_object(self, param, json_key):

        self.debug_print("param", param)

        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        input_object = param[json_key]

        try:
            self._parsed_whois_domain(input_object, action_result)
        except Exception as e:
            self.debug_print(e)

        try:
            if not action_result.get_status() == phantom.APP_SUCCESS:
                self._regular_whois_domain(input_object, action_result)
        except Exception as e:
            message = 'Error while querying input_object'
            action_result.set_status(phantom.APP_ERROR, message, e)
            return action_result.get_status()

        if (phantom.is_fail(action_result.get_status())):
            return action_result.get_status()

        data = action_result.get_data()

        if (not data):
            return action_result.get_status()

        response = data[0]

        if response and 'registrant' in response:
            # get the registrant
            summary = {'organization': response['registrant']}
            if 'parsed_whois' in response:
                contacts = response['parsed_whois'].get('contacts', {})
                if type(contacts) == list:
                    registrant = contacts[0]
                else:
                    registrant = contacts.get('registrant')
                summary['city'] = registrant.get('city')
                summary['country'] = registrant.get('country')
                action_result.update_summary(summary)

        return action_result.get_status()

    def _handle_whois_history(self, param):

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = 'whois/history'

        self.debug_print("param", param)
        self.debug_print("endpoint", endpoint)

        domain = param[self.DOMAIN_KEY]

        ret_val = self._do_query(domain, endpoint, action_result)

        if (not ret_val):
            return action_result.get_data()

        data = action_result.get_data()

        if (not data):
            return action_result.get_status()

        self._convert_dict_to_list(data, 'history')

        try:
            # set the summary
            action_result.update_summary({self.HISTORY_ITEMS: data[0]['record_count']})
        except:
            pass

        return action_result.get_status()

    def _handle_hosting_history(self, param):

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = 'hosting-history'

        self.debug_print("param", param)
        self.debug_print("endpoint", endpoint)

        domain = param[self.DOMAIN_KEY]

        ret_val = self._do_query(domain, endpoint, action_result)

        if (not ret_val):
            return action_result.get_data()

        data = action_result.get_data()

        if (not data):
            return action_result.get_status()

        self._convert_dict_to_list(data, 'registrar_history')
        self._convert_dict_to_list(data, 'ip_history')
        self._convert_dict_to_list(data, 'nameserver_history')

        # set the summary
        try:
            action_result.update_summary({self.REGISTRAR_HIST: len(data[0]['registrar_history'])})
        except:
            action_result.update_summary({self.REGISTRAR_HIST: 0})

        try:
            action_result.update_summary({self.IP_HIST: len(data[0]['ip_history'])})
        except:
            action_result.update_summary({self.IP_HIST: 0})

        try:
            action_result.update_summary({self.NS_HIST: len(data[0]['nameserver_history'])})
        except:
            action_result.update_summary({self.NS_HIST: 0})

        return action_result.get_status()

    def _convert_dict_to_list(self, data, key):

        if (not data):
            return

        try:
            value = data[0][key]
            if (type(value) != list):
                data[0][key] = [value]
        except Exception as e:
            self.debug_print('Handled exception while converting data from dict to list', e)
            return phantom.APP_ERROR

        return phantom.APP_SUCCESS

    def _handle_reverse_domain(self, param):

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = 'reverse-ip'

        self.debug_print("param", param)
        self.debug_print("endpoint", endpoint)

        domain = param[self.DOMAIN_KEY]

        ret_val = self._do_query(domain, endpoint, action_result, ignore400=True)

        if (not ret_val):
            return action_result.get_data()

        data = action_result.get_data()

        if (not data):
            return action_result.get_status()

        # convert the ip_addresses key to list if dictionary
        self._convert_dict_to_list(data, 'ip_addresses')

        # set the summary
        try:
            action_result.update_summary({self.IPS_COUNT: len(data[0]['ip_addresses'])})
        except:
            action_result.update_summary({self.IPS_COUNT: 0})

        return action_result.get_status()

    def _handle_reverse_ip(self, param):

        # Add an action result to the App Run
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = 'host-domains'
        self.debug_print("param", param)
        self.debug_print("endpoint", endpoint)

        ip = param[self.IP_KEY]

        ret_val = self._do_query(ip, endpoint, action_result)

        if (not ret_val):
            return action_result.get_status()

        data = action_result.get_data()

        # set the summary
        try:
            action_result.update_summary({self.DOMAINS_COUNT: data[0]['ip_addresses']['domain_count']})
        except:
            action_result.update_summary({self.DOMAINS_COUNT: 0})

        return action_result.get_status()


    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        # Get the config
        config = self.get_config()

        self._username = config['username']
        self._key = config['key']

        if action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            ret_val = self._test_connectivity(param)
        elif action_id == self.ACTION_ID_WHOIS_IP:
            ret_val = self._whois_object(param, self.IP_KEY)
        elif action_id == self.ACTION_ID_WHOIS_DOMAIN:
            ret_val = self._whois_object(param, self.DOMAIN_KEY)
        elif action_id == self.ACTION_ID_WHOIS_HISTORY:
            ret_val = self._handle_whois_history(param)
        elif action_id == self.ACTION_ID_HOSTING_HISTORY:
            ret_val = self._handle_hosting_history(param)
        elif action_id == self.ACTION_ID_REVERSE_DOMAIN:
            ret_val = self._handle_reverse_domain(param)
        elif action_id == self.ACTION_ID_REVERSE_IP:
            ret_val = self._handle_reverse_ip(param)
        elif action_id == self.ACTION_ID_REVERSE_EMAIL:
            ret_val = self._handle_reverse_whois_email(param)
        elif action_id == self.ACTION_ID_BRAND_MONITOR:
            ret_val = self._brand_monitor(param)
        elif action_id == self.ACTION_ID_DOMAIN_REPUTATION:
            ret_val = self._domain_reputation(param)

        return ret_val


if __name__ == '__main__':

    import sys
    import pudb

    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = DomainToolsConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
