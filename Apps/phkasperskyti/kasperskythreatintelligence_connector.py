# File: kasperskythreatintelligence_connector.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
# -----------------------------------------
# Kaspersky Threat Intelligence App Connector for Splunk Phantom
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

# Local imports
from kasperskythreatintelligence_consts import *

import requests
import json
import tempfile
import os
import re
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class KasperskyThreatIntelligenceConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(KasperskyThreatIntelligenceConnector, self).__init__()

        self._state = None
        self._base_url = None
        self._username = None
        self._password = None
        self._pem_key = None
        self._tmp_pem_file = None
        self._key_tmp_name = None
        self._eula = None
        self._policy = None

    def _extract_kaspersky_summary(self, response):
        # Generate the OTX summary
        summary = self._init_summary()
        tmp_indicator = ''

        if 'Zone' in response:
            summary = self._get_zone_info(response, summary)

        if 'DomainGeneralInfo' in response:
            summary, tmp_indicator = self._get_domain_info(response, summary)

        if 'IpGeneralInfo' in response:
            summary, tmp_indicator = self._get_ip_info(response, summary)

        if 'FileGeneralInfo' in response:
            summary, tmp_indicator = self._get_file_info(response, summary)

        if 'UrlGeneralInfo' in response:
            summary, tmp_indicator = self._get_url_info(response, summary)

        if 'LicenseInfo' in response:
            if response['LicenseInfo']['DayRequests']:
                summary['DayRequests'] = response['LicenseInfo']['DayRequests']
            if response['LicenseInfo']['DayQuota']:
                summary['DayQuota'] = response['LicenseInfo']['DayQuota']

        summary['tip_url'] = 'https://tip.kaspersky.com/search?searchString=' + tmp_indicator

        if 'return_data' in response:
            if response['return_data']['name']:
                summary['apt_report'] = response['return_data']['name']

            summary['apt_url'] = 'https://tip.kaspersky.com/reporting?id=' + response['return_data']['id']

            if response['return_data']['desc']:
                summary['apt_report_desc'] = response['return_data']['desc']

            if response['return_data']['tags_geo']:
                summary['apt_report_geo'] = response['return_data']['tags_geo']

            if response['return_data']['tags_industry']:
                summary['apt_report_industry'] = response['return_data']['tags_industry']

            if response['return_data']['tags_actors']:
                summary['apt_report_actors'] = response['return_data']['tags_actors']

        return summary

    def _init_summary(self):
        # initialize summary var
        summary = dict()
        summary['found'] = False
        summary['count'] = 0
        summary['zone'] = "Grey"
        summary['categories'] = []
        summary['threat_score'] = 0
        summary['DayRequests'] = 0
        summary['DayQuota'] = 0
        summary['hits_count'] = 0
        summary['hash'] = ''
        summary['sha1'] = ''
        summary['sha2'] = ''
        summary['tip_url'] = ''
        summary['apt_related'] = False
        summary['apt_report'] = None
        summary['apt_url'] = ''
        summary['apt_report_id'] = ''
        summary['apt_report_desc'] = ''
        summary['apt_report_geo'] = ''
        summary['apt_report_industry'] = ''
        summary['apt_report_actors'] = ''
        return summary

    def _get_zone_info(self, response, summary):
        # get info about object zone
        if response['Zone'] != "Grey":
            summary['found'] = True
            summary['count'] = 1
            summary['zone'] = response['Zone']
        return summary

    def _get_domain_info(self, response, summary):
        # get info about requested domain
        tmp_indicator = response['DomainGeneralInfo']['Domain']
        summary['hits_count'] = response['DomainGeneralInfo']['HitsCount']
        if len(response['DomainGeneralInfo']['Categories']) > 0:
            summary['categories'] = response['DomainGeneralInfo']['Categories']

        if response['DomainGeneralInfo']['HasApt']:
            summary['apt_related'] = True
            if len(response['DomainGeneralInfo']['RelatedAptReports']) > 0:
                summary['apt_report'] = response['DomainGeneralInfo']['RelatedAptReports'][0]['Title']
                summary['apt_report_id'] = response['DomainGeneralInfo']['RelatedAptReports'][0]['Id']
        return summary, tmp_indicator

    def _get_url_info(self, response, summary):
        tmp_indicator = response['UrlGeneralInfo']['Url']
        if len(response['UrlGeneralInfo']['Categories']) > 0:
            summary['categories'] = response['UrlGeneralInfo']['Categories']

        if response['UrlGeneralInfo']['HasApt']:
            summary['apt_related'] = True
            if len(response['UrlGeneralInfo']['RelatedAptReports']) > 0:
                summary['apt_report'] = response['UrlGeneralInfo']['RelatedAptReports'][0]['Title']
                summary['apt_report_id'] = response['UrlGeneralInfo']['RelatedAptReports'][0]['Id']
        return summary, tmp_indicator

    def _get_ip_info(self, response, summary):
        # get info about requested ip
        tmp_indicator = response['IpGeneralInfo']['Ip']
        summary['hits_count'] = response['IpGeneralInfo']['HitsCount']
        if len(response['IpGeneralInfo']['Categories']) > 0:
            summary['categories'] = response['IpGeneralInfo']['Categories']

        if response['IpGeneralInfo']['HasApt']:
            summary['apt_related'] = True
            if len(response['IpGeneralInfo']['RelatedAptReports']) > 0:
                summary['apt_report'] = response['IpGeneralInfo']['RelatedAptReports'][0]['Title']
                summary['apt_report_id'] = response['IpGeneralInfo']['RelatedAptReports'][0]['Id']

        if response['IpGeneralInfo']['ThreatScore']:
            summary['threat_score'] = response['IpGeneralInfo']['ThreatScore']
        return summary, tmp_indicator

    def _get_file_info(self, response, summary):
        # get info about requested file
        tmp_indicator = response['FileGeneralInfo']['Md5']
        summary['hits_count'] = response['FileGeneralInfo']['HitsCount']
        if response.get('DetectionsInfo'):
            if len(response['DetectionsInfo']) > 0:
                for categories in response['DetectionsInfo']:
                    summary['categories'].append(categories['DetectionName'])
                    if len(summary['categories']) == int(self._recordcount):
                        break
        else:
            summary['categories'] = '-'

        if response['FileGeneralInfo']['Md5']:
            summary['hash'] = response['FileGeneralInfo']['Md5']

        if response['FileGeneralInfo']['Sha1']:
            summary['sha1'] = response['FileGeneralInfo']['Sha1']

        if response['FileGeneralInfo']['Sha256']:
            summary['sha2'] = response['FileGeneralInfo']['Sha256']

        if response['FileGeneralInfo']['HasApt']:
            summary['apt_related'] = True
            if len(response['FileGeneralInfo']['RelatedAptReports']) > 0:
                summary['apt_report'] = response['FileGeneralInfo']['RelatedAptReports'][0]['Title']
                summary['apt_report_id'] = response['FileGeneralInfo']['RelatedAptReports'][0]['Id']
        return summary, tmp_indicator

    def _prepare_url(self, url_input):
        # prepare url for send
        url_input = url_input.lower()
        url_input = url_input.replace('..', '.')
        url_input = url_input.replace('./', '/')
        creds = re.search(r'^\S+\:\/\/(\S+(\:\S+){0,1}\@).*?', url_input)
        if creds:
            url_input = url_input.replace(creds.group(1), '')
        port = re.search(r'^\S+\:\/\/\S+(\:\d+)(?:\/|$)', url_input)
        if port:
            url_input = url_input.replace(port.group(1), '')
        dot = re.search(r'^\S+\:\/\/\S+(\.)\/', url_input)
        if dot:
            url_input = url_input[:-2]
        protocol = re.search(r'^(\S+\:\/\/).*?', url_input)
        if protocol:
            url_input = url_input.replace(protocol.group(1), '')
        www = re.search(r'^(www\.).*?', url_input)
        if www:
            url_input = url_input.replace(www.group(1), '')
        endslash = re.search(r'^.*?(\/)$', url_input)
        if endslash:
            url_input = url_input[:-1]
        endfragment = re.search(r'^.*?(\#\w+)$', url_input)
        if endfragment:
            url_input = url_input.replace(endfragment.group(1), '')
        while re.search(r'(?:.*?)(\/\/)(?:.*?)', url_input):
            url_input = url_input.replace('//', '/')
        url_output = url_input.replace("/", "%2F")
        url_output = url_output.replace(" ", "%20")
        url_output = url_output.replace("!", "%21")
        url_output = url_output.replace("$", "%24")
        url_output = url_output.replace("&", "%26")
        url_output = url_output.replace("'", "%27")
        url_output = url_output.replace("(", "%28")
        url_output = url_output.replace(")", "%29")
        url_output = url_output.replace("*", "%2A")
        url_output = url_output.replace("+", "%2B")
        url_output = url_output.replace(",", "%2C")
        url_output = url_output.replace(";", "%3B")
        url_output = url_output.replace("=", "%3D")
        url_output = url_output.replace(":", "%3A")
        url_output = url_output.replace("?", "%3F")
        url_output = url_output.replace("#", "%23")
        url_output = url_output.replace("[", "%5B")
        url_output = url_output.replace("]", "%5D")
        url_output = url_output.replace("@", "%40")
        return url_output

    def _validate_integer(self, action_result, parameter, key):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, "Please provide a valid integer value in the {}".format(key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, "Please provide a valid integer value in the {}".format(key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, "Please provide a valid non-negative integer value in the {}".format(key)), None

        return phantom.APP_SUCCESS, parameter

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

    def _process_empty_response(self, response, action_result):
        # process the empty response from KL TIP
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Status Code: {0}. Empty response and no information in the header".format(status_code)), None)

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
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            error_text = "Cannot parse error details: {0}".format(err)

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. {0}".format(err)), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        return self._process_json_response(r, action_result)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        url = f"{self._base_url}{endpoint}"
        username = self._username
        password = self._password
        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        try:
            r = request_func(
                            url,
                            auth=(username, password),
                            verify=config.get('verify_server_cert', False),
                            cert=self._key_tmp_name,
                            **kwargs)
            if '403' in str(r):
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Your account does not have access to the Kaspersky Threat Intelligence Portal API"), resp_json)
            if '401' in str(r):
                return RetVal(action_result.set_status(phantom.APP_ERROR, "You did not accept the terms and conditions of Kaspersky Threat Intelligence Portal"), resp_json)
            if '400' in str(r) or '404' in str(r):
                return RetVal(action_result.set_status(phantom.APP_ERROR, "No search result. Please check your request and try again later"), resp_json)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {0}".format(err)), resp_json)
        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, response = self._make_rest_call('/api/domain/example.com?sections=Zone,LicenseInfo', action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        try:
            summary = action_result.update_summary(self._extract_kaspersky_summary(response))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return self.set_status(phantom.APP_ERROR, f"Error occurred while processing server response. {err}")

        self.save_progress('_____________________________________________________________')
        self.save_progress('Day quota: ' + str(summary['DayQuota']))
        self.save_progress('Day requests: ' + str(summary['DayRequests']))
        self.save_progress('_____________________________________________________________')
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_domain_reputation(self, param):
        # get domain reputation
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param['domain']
        endpoint = f"/api/domain/{domain}?sections=Zone,DomainGeneralInfo"
        self.debug_print(domain)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        try:
            summary = action_result.update_summary(self._extract_kaspersky_summary(response))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return self.set_status(phantom.APP_ERROR, f"Error occurred while processing server response. {err}")
        self.debug_print(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_ip_reputation(self, param):
        # get ip reputation
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param['ip']
        endpoint = f"/api/ip/{ip}?sections=Zone,IpGeneralInfo"
        self.debug_print(ip)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        try:
            summary = action_result.update_summary(self._extract_kaspersky_summary(response))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return self.set_status(phantom.APP_ERROR, f"Error occurred while processing server response. {err}")
        self.debug_print(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_file_reputation(self, param):
        # get file reputation
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        hash_value = param['hash']
        self.debug_print(hash_value)
        endpoint = f"/api/hash/{hash_value}?sections=Zone,FileGeneralInfo,DetectionsInfo"

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        try:
            summary = action_result.update_summary(self._extract_kaspersky_summary(response))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return self.set_status(phantom.APP_ERROR, f"Error occurred while processing server response. {err}")
        self.debug_print(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_url_reputation(self, param):
        # get url reputation
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        url = param['url']
        self.debug_print(url)
        endpoint = f"/api/url/{self._prepare_url(url)}?sections=Zone,UrlGeneralInfo"

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        try:
            summary = action_result.update_summary(self._extract_kaspersky_summary(response))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return self.set_status(phantom.APP_ERROR, f"Error occurred while processing server response. {err}")
        self.debug_print(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def type_of_indicator(self, indicator):
        i = re.search(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', indicator)
        if i:
            return f"/api/ip/{indicator}"
        i = re.search(r'^([\da-fA-F]{32,64})', indicator)
        if i:
            return f"/api/hash/{indicator}"
        i = re.search(r'^(\S+\:\/\/.*)', indicator)
        if i:
            return f"/api/url/{self._prepare_url(indicator)}"
        return f"/api/domain/{indicator}"

    def _handle_get_more_info(self, param):
        # get url reputation
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        indicator = param['indicator']
        self.debug_print(indicator)
        endpoint = f"{self.type_of_indicator(indicator)}?count={self._recordcount}"
        if param.get('sections'):
            endpoint += f"&sections={param.get('sections')}"

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        try:
            summary = action_result.update_summary(self._extract_kaspersky_summary(response))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return self.set_status(phantom.APP_ERROR, f"Error occurred while processing server response. {err}")
        self.debug_print(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_reports(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        apt_id = param['apt_id']
        self.debug_print(apt_id)
        endpoint = f"/api/publications/get_one?publication_id={apt_id}&include_info=all"

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        try:
            summary = action_result.update_summary(self._extract_kaspersky_summary(response))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return self.set_status(phantom.APP_ERROR, f"Error occurred while processing server response. {err}")
        self.debug_print(summary)
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'domain_reputation':
            ret_val = self._handle_domain_reputation(param)

        elif action_id == 'ip_reputation':
            ret_val = self._handle_ip_reputation(param)

        elif action_id == 'file_reputation':
            ret_val = self._handle_file_reputation(param)

        elif action_id == 'url_reputation':
            ret_val = self._handle_url_reputation(param)

        elif action_id == 'get_reports':
            ret_val = self._handle_get_reports(param)

        elif action_id == 'get_more_info':
            ret_val = self._handle_get_more_info(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        config = self.get_config()

        self._eula = config.get('accept_the_terms_and_conditions')
        self._policy = config.get('accept_privacy_policy')
        self._base_url = 'https://tip.kaspersky.com'
        self._username = config.get('username')
        self._password = config.get('password')
        self._recordcount = config.get('records_count')
        # Validate 'self._recordcount' configuration parameter
        ret_val, self._recordcount = self._validate_integer(self, self._recordcount, RECORD_COUNT_KEY)
        if phantom.is_fail(ret_val):
            return self.get_status()

        if not self._eula or not self._policy:
            return self.set_status(phantom.APP_ERROR, "Please accept Terms and conditions and Privacy Policy")

        if hasattr(Vault, 'get_vault_tmp_dir'):
            temp_dir = Vault.get_vault_tmp_dir()
        else:
            temp_dir = "/opt/phantom/vault/tmp/"

        try:
            self._tmp_pem_file = tempfile.NamedTemporaryFile(dir=temp_dir, mode='w+b', delete=False)
            self._tmp_pem_file.write(str.encode(config.get('pem_key')))
            self._key_tmp_name = self._tmp_pem_file.name
            self._tmp_pem_file.close()
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return self.set_status(phantom.APP_ERROR, err)

        return phantom.APP_SUCCESS

    def finalize(self):
        if self._key_tmp_name and os.path.exists(self._key_tmp_name):
            os.unlink(self._key_tmp_name)

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

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
            login_url = KasperskyThreatIntelligenceConnector._get_phantom_base_url() + '/login'

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

        connector = KasperskyThreatIntelligenceConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
