# File: whois_connector.py
# Copyright (c) 2016-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Phantom imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# THIS Connector imports
from whois_consts import *

import simplejson as json
import pythonwhois
import datetime
import time
from ipwhois import IPWhois
from ipwhois import IPDefinedError
from bs4 import UnicodeDammit
import tldextract
import ipaddress

TLD_LIST_CACHE_FILE_NAME = "public_suffix_list.dat"
ISO_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'


def _json_fallback(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    else:
        return obj


class WhoisConnector(BaseConnector):

    # actions supported by this script
    ACTION_ID_WHOIS_DOMAIN = "whois_domain"
    ACTION_ID_WHOIS_IP = "whois_ip"

    def __init__(self):

        # Call the BaseConnectors init first
        super(WhoisConnector, self).__init__()

        self._state_file_path = None
        self._cache_file_path = None
        self._state = {}

    def initialize(self):
        self._state = self.load_state()
        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _response_no_data(self, response, obj):

        contacts = response['contacts']

        # First check if the raw data contains any info
        raw_response = phantom.get_value(response, 'raw')
        if (raw_response):
            for line in raw_response:
                if (line.lower().find('domain not found') != -1):
                    self.debug_print('Matched No data string', 'Domain not found')
                    return True
                if (line.lower().find("no match for '{0}'".format(obj).lower()) != -1):
                    self.debug_print('Matched No data string', 'no match for domain')
                    return True

        # Check if none of the data that we need is present or not
        if (not contacts.get('admin')) and (not contacts.get('tech')) and (not contacts.get('registrant')) and (not contacts.get('billing')):
            return True

        return False

    def _whois_ip(self, param):

        ip = param[phantom.APP_JSON_IP]

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Validation for checking valid IP or not (IPV4 as well as IPV6)
        if not self._is_ip(ip):
            return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid IPV4 or IPV6 address')

        action_result.set_param({phantom.APP_JSON_IP: ip})

        self.debug_print("Validating/Querying IP '{0}'".format(ip))

        self.save_progress("Querying...")

        try:
            obj_whois = IPWhois(ip)
            whois_response = obj_whois.lookup_whois(asn_methods=['whois', 'dns', 'http'])
        except IPDefinedError as e_defined:
            self.debug_print("Got IPDefinedError exception str: {0}".format(str(e_defined)))
            return action_result.set_status(phantom.APP_SUCCESS, str(e_defined))
        except Exception as e:
            self.debug_print("Got exception: type: {0}, str: {1}".format(type(e).__name__, str(e)))
            return action_result.set_status(phantom.APP_ERROR, WHOIS_ERR_QUERY, e)

        if not whois_response:
            return action_result.set_status(phantom.APP_ERROR, WHOIS_ERR_QUERY_RETURNED_NO_DATA)

        self.save_progress("Parsing response")

        action_result.add_data(whois_response)

        summary = action_result.update_summary({})
        message = ''

        # Create the summary and the message
        if ('asn_registry' in whois_response):
            summary.update({WHOIS_JSON_ASN_REGISTRY: whois_response['asn_registry']})
            message += 'Registry: {0}'.format(summary[WHOIS_JSON_ASN_REGISTRY])

        if ('asn' in whois_response):
            summary.update({WHOIS_JSON_ASN: whois_response['asn']})
            message += '\nASN: {0}'.format(summary[WHOIS_JSON_ASN])

        if ('asn_country_code' in whois_response):
            summary.update({WHOIS_JSON_COUNTRY_CODE: whois_response['asn_country_code']})
            message += '\nCountry: {0}'.format(summary[WHOIS_JSON_COUNTRY_CODE])

        if ('nets' in whois_response):
            nets = whois_response['nets']
            wanted_keys = ['range', 'address']
            summary[WHOIS_JSON_NETS] = []
            message += '\nNets:'
            for net in nets:
                summary_net = {x: net[x] for x in wanted_keys}
                summary[WHOIS_JSON_NETS].append(summary_net)
                message += '\nRange: {0}'.format(summary_net['range'])
                message += '\nAddress: {0}'.format(summary_net['address'])

        action_result.set_status(phantom.APP_SUCCESS, message)

        # This sleep is required between two calls, else the server might
        # throttle the queries when done in quick succession, which leads
        # to a 'Connection reset by peer' error.
        time.sleep(1)

    def _is_ip(self, input_ip_address):
        """ Function that checks given address and return True if address is valid IPv4 or IPV6 address.

        :param input_ip_address: IP address
        :return: status (success/failure)
        """

        ip_address_input = input_ip_address

        try:
            try:
                ipaddress.ip_address(unicode(ip_address_input))
            except NameError:
                ipaddress.ip_address(str(ip_address_input))
        except:
            return False

        return True

    def _should_update_cache(self):

        last_time = self._state.get(WHOIS_JSON_CACHE_UPDATE_TIME)

        if (not last_time):
            return True

        try:
            last_time = datetime.datetime.strptime(last_time, ISO_TIME_FORMAT)
        except Exception as e:
            self.debug_print("Exception while strptime", e)
            return True

        current_time = datetime.datetime.utcnow()

        time_diff = current_time - last_time

        app_config = self.get_app_config()
        cache_exp_days = int(app_config[WHOIS_JSON_CACHE_EXP_DAYS])

        if (time_diff.days >= cache_exp_days):
            self.debug_print("Diff days {0} >= cache exp days {1}".format(time_diff.days, cache_exp_days))
            return True

        return False

    def _get_domain(self, hostname):

        extract = None

        should_update = self._should_update_cache()
        try:
            if (should_update):
                self.debug_print("Will Update tld list on the current call")
                extract = tldextract.TLDExtract(cache_file=self._cache_file_path)
            else:
                extract = tldextract.TLDExtract(cache_file=self._cache_file_path, suffix_list_urls=None)
        except Exception as e:
            self.debug_print("tldextract result failed", e)
            # The caller of this function has a try..except for this one
            raise

        result = extract(hostname)

        if (should_update):
            # Set the updated time
            self._state[WHOIS_JSON_CACHE_UPDATE_TIME] = datetime.datetime.utcnow().strftime(ISO_TIME_FORMAT)

        domain = ""
        if result.suffix and result.domain:
            domain = "{0}.{1}".format(result.domain, result.suffix)  # pylint: disable=E1101
        elif result.suffix:
            domain = "{0}".format(result.suffix)  # pylint: disable=E1101
        elif result.domain:
            domain = "{0}".format(result.domain)  # pylint: disable=E1101

        return domain

    def _fetch_whois_info(self, action_result, domain, server):
        '''
        This method fetches the whois information for the given domain based on the
        value of the server if provided or by using the default server of the pythonwhois library.
        '''

        try:
            self.debug_print("Fetching the WHOIS information. Server is: {}".format(server))
            if server:
                raw_whois_resp = pythonwhois.net.get_whois_raw(domain, server)
                whois_response = pythonwhois.parse.parse_raw_whois(raw_whois_resp)
            else:
                whois_response = pythonwhois.get_whois(domain)
        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, WHOIS_ERR_QUERY, e)
            return None

        if not whois_response:
            action_result.set_status(phantom.APP_ERROR, WHOIS_ERR_QUERY_RETURNED_NO_DATA)
            return None

        return whois_response

    def _whois_domain(self, param):

        config = self.get_config()

        server = config.get(phantom.APP_JSON_SERVER, None)

        domain = param[phantom.APP_JSON_DOMAIN]

        action_result = self.add_action_result(ActionResult(dict(param)))

        action_result.set_param({phantom.APP_JSON_DOMAIN: domain})

        # This sleep is required between two calls, else the server might
        # throttle the queries when done in quick succession, which leads
        # to a 'Connection reset by peer' error.
        # Sleep before doing anything (as opposed to after), so that even
        # if this action returns an error, the sleep will get executed and
        # the next call will get executed after this sleep
        time.sleep(1)

        try:
            domain = self._get_domain(domain)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, WHOIS_ERR_PARSE_INPUT, e)

        self.debug_print("Validating/Querying Domain {0}".format(repr(domain)))

        action_result.update_summary({phantom.APP_JSON_DOMAIN: domain})

        self.save_progress("Querying...")

        # 1. Attempting to fetch the whois information with the server
        # if provided or without it if not provided
        whois_response = self._fetch_whois_info(action_result, domain, server)

        if whois_response is None:
            return action_result.get_status()

        # 2. Attempting to fetch the whois information with the server obtained
        # in the output response of the first step above
        if whois_response.get('contacts') and not whois_response.get('contacts').get('registrant'):
            if whois_response.get('whois_server'):
                resp_server = UnicodeDammit(whois_response.get('whois_server')[0]).unicode_markup.encode('utf-8')

                whois_response = self._fetch_whois_info(action_result, domain, resp_server)

                if whois_response is None:
                    return action_result.get_status()
            else:
                self.debug_print("No second API call required as the server information could not be fetched from the first WHOIS API call")

        self.save_progress("Parsing response")

        try:
            # Need to work on the json, it contains certain fields that are not
            # parsable, so will need to go the 'fallback' way.
            # TODO: Find a better way to do this
            whois_response = json.dumps(whois_response, default=_json_fallback)
            whois_response = json.loads(whois_response)
            action_result.add_data(whois_response)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, WHOIS_ERR_PARSE_REPLY, e)

        # Even if the query was successfull the data might not be available
        if (self._response_no_data(whois_response, domain)):
            return action_result.set_status(phantom.APP_SUCCESS, '{}, but, {}.'.format(WHOIS_SUCC_QUERY, WHOIS_ERR_QUERY_RETURNED_NO_CONTACTS_DATA))
        else:
            # get the registrant
            if whois_response.get('contacts') and whois_response.get('contacts').get('registrant'):
                registrant = whois_response['contacts']['registrant']
                wanted_keys = ['organization', 'name', 'city', 'country']
                summary = {x: registrant[x] for x in wanted_keys if x in registrant}
                action_result.update_summary(summary)
                action_result.set_status(phantom.APP_SUCCESS)
            else:
                action_result.set_status(phantom.APP_SUCCESS, '{}, but, {}.'.format(WHOIS_SUCC_QUERY, WHOIS_SUCC_QUERY_RETURNED_NO_REGISTRANT_DATA))

        return phantom.APP_SUCCESS

    def handle_action(self, param):
        """Function that handles all the actions

        Args:

        Return:
            A status code
        """

        result = None
        action = self.get_action_identifier()

        if (action == self.ACTION_ID_WHOIS_DOMAIN):
            result = self._whois_domain(param)
        elif (action == self.ACTION_ID_WHOIS_IP):
            result = self._whois_ip(param)
        else:
            result = self.unknown_action()

        return result


if __name__ == '__main__':

    import sys
    # import simplejson as json
    import pudb

    pudb.set_trace()

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=' ' * 4))

        connector = WhoisConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
