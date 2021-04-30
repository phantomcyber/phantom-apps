# -----------------------------------------
# Kaspersky Threat Intelligence App Connector for Splunk Phantom
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

import requests
import json
import tempfile
import os
import re
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class KasperskyTIConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(KasperskyTIConnector, self).__init__()

        self._state = None
        self._base_url = None
        self._username = None
        self._password = None
        self._pem_key = None
        self._tmp_pem_file = None
        self._key_tmp_name = None
        self._eula = None
        self._policy = None

    def _add_zoneInfo(self, response, summary):
        if response['Zone'] != "Grey":
            summary['found'] = True
            summary['count'] = 1
            summary['zone'] = response['Zone']

        return summary

    def _add_domaininfo(self, response, summary):
        summary['hits_count'] = response['DomainGeneralInfo']['HitsCount']
        if len(response['DomainGeneralInfo']['Categories']) > 0:
            summary['categories'] = response['DomainGeneralInfo']['Categories']

        if response['DomainGeneralInfo']['HasApt']:
            summary['apt_related'] = True
            if len(response['DomainGeneralInfo']['RelatedAptReports']) > 0:
                summary['apt_report'] = response['DomainGeneralInfo']['RelatedAptReports'][0]['Title']
                summary['apt_report_id'] = response['DomainGeneralInfo']['RelatedAptReports'][0]['Id']

        return summary

    def _add_ipinfo(self, response, summary):
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

        return summary

    def _add_fileinfo(self, response, summary):
        summary['hits_count'] = response['FileGeneralInfo']['HitsCount']
        if 'DetectionsInfo' in response:
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

        return summary

    def _add_licenseinfo(self, response, summary):
        if response['LicenseInfo']['DayRequests']:
            summary['DayRequests'] = response['LicenseInfo']['DayRequests']
        if response['LicenseInfo']['DayQuota']:
            summary['DayQuota'] = response['LicenseInfo']['DayQuota']

        return summary

    def _add_urlinfo(self, response, summary):
        if len(response['UrlGeneralInfo']['Categories']) > 0:
            summary['categories'] = response['UrlGeneralInfo']['Categories']

        if response['UrlGeneralInfo']['HasApt']:
            summary['apt_related'] = True
            if len(response['UrlGeneralInfo']['RelatedAptReports']) > 0:
                summary['apt_report'] = response['UrlGeneralInfo']['RelatedAptReports'][0]['Title']
                summary['apt_report_id'] = response['UrlGeneralInfo']['RelatedAptReports'][0]['Id']

        return summary

    def _add_returndata(self, response, summary):
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

    def _extract_kaspersky_summary(self, response):

        # Generate the OTX summary
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

        summary['apt_related'] = False
        summary['apt_report'] = None
        summary['apt_url'] = ''
        summary['apt_report_id'] = ''
        summary['apt_report_desc'] = ''
        summary['apt_report_geo'] = ''
        summary['apt_report_industry'] = ''
        summary['apt_report_actors'] = ''

        tmp_indicator = ''
        summary['tip_url'] = ''

        if 'Zone' in response:
            summary = self._add_zoneInfo(response, summary)

        if 'DomainGeneralInfo' in response:
            tmp_indicator = response['DomainGeneralInfo']['Domain']
            summary = self._add_domaininfo(response, summary)

        if 'IpGeneralInfo' in response:
            tmp_indicator = response['IpGeneralInfo']['Ip']
            summary = self._add_ipinfo(response, summary)

        if 'FileGeneralInfo' in response:
            tmp_indicator = response['FileGeneralInfo']['Md5']
            summary = self._add_fileinfo(response, summary)

        if 'LicenseInfo' in response:
            summary = self.add_licenseinfo(response, summary)

        if 'UrlGeneralInfo' in response:
            tmp_indicator = response['UrlGeneralInfo']['Url']
            summary = self._add_urlinfo(response, summary)

        summary['tip_url'] = 'https://tip.kaspersky.com/search?searchString=' + tmp_indicator

        if 'return_data' in response:
            summary = self._add_returndata(response, summary)

        return summary

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

    def _process_empty_response(self, response, action_result):
        # process the empty response from KL TIP
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace(u'{', '{{').replace(u'}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        if not r.text:
            return self._process_empty_response(r, action_result)

        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        url = self._base_url + endpoint
        username = self._username
        password = self._password
        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, u"Invalid method: {0}".format(method)), resp_json)

        try:
            r = request_func(
                            url,
                            auth=(username, password),
                            verify=config.get('verify_server_cert', False),
                            cert=self._key_tmp_name,
                            **kwargs)
            if '403' in str(r):
                return RetVal(action_result.set_status( phantom.APP_ERROR, "Your account does not have access to the Kaspersky Threat Intelligence Portal API"), resp_json)
            if '401' in str(r):
                return RetVal(action_result.set_status( phantom.APP_ERROR, "You did not accept the terms and conditions of Kaspersky Threat Intelligence Portal"), resp_json)
            if '400' in str(r) or '404' in str(r):
                return RetVal(action_result.set_status( phantom.APP_ERROR, "No search result. Please check your request and try again later"), resp_json)
        except Exception as e:
            os.unlink(self._key_tmp_name)
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)
        os.unlink(self._key_tmp_name)
        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, response = self._make_rest_call('/api/domain/example.com?sections=Zone,LicenseInfo', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        summary = action_result.update_summary(self._extract_kaspersky_summary(response))
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
        endpoint = "/api/domain/" + domain + "?sections=Zone,DomainGeneralInfo"
        self.debug_print(domain)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary(self._extract_kaspersky_summary(response))
        self.debug_print(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_ip_reputation(self, param):
        # get ip reputation
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param['ip']
        endpoint = "/api/ip/" + ip + "?sections=Zone,IpGeneralInfo"
        self.debug_print(ip)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary(self._extract_kaspersky_summary(response))
        self.debug_print(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_file_reputation(self, param):
        # get file reputation
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        hash = param['hash']
        self.debug_print(hash)
        endpoint = "/api/hash/" + hash + "?sections=Zone,FileGeneralInfo,DetectionsInfo"

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary(self._extract_kaspersky_summary(response))
        self.debug_print(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_url_reputation(self, param):
        # get url reputation
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        url = param['url']
        self.debug_print(url)
        endpoint = "/api/url/" + self._prepare_url(url) + "?sections=Zone,UrlGeneralInfo"

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary(self._extract_kaspersky_summary(response))
        self.debug_print(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def type_of_indicator(self, indicator):
        import re
        i = re.search(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', indicator)
        if i:
            return "/api/ip/" + indicator
        i = re.search(r'^([\da-fA-F]{32,64})', indicator)
        if i:
            return "/api/hash/" + indicator
        i = re.search(r'^(\S+\:\/\/.*)', indicator)
        if i:
            return "/api/url/" + self._prepare_url(indicator)
        return "/api/domain/" + indicator

    def _handle_get_more_info(self, param):
        # get url reputation
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        indicator = param['indicator']
        self.debug_print(indicator)
        endpoint = self.type_of_indicator(indicator) + "?count=" + str(self._recordcount)
        if 'sections' in param:
            endpoint += '&sections=' + param['sections']

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary(self._extract_kaspersky_summary(response))
        self.debug_print(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_reports(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        apt_id = param['apt_id']
        self.debug_print(apt_id)
        endpoint = "/api/publications/get_one?publication_id=" + apt_id + "&include_info=all"

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)
        summary = action_result.update_summary(self._extract_kaspersky_summary(response))
        self.debug_print(summary)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        if not self._eula or not self._policy:
            action_result = self.add_action_result(ActionResult(dict(param)))
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Please accept Terms and conditions and Privacy Policy"), None)

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

        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """
        self._eula = config.get('accept the terms and conditions')
        self._policy = config.get('accept Privacy Policy')
        self._base_url = 'https://tip.kaspersky.com'
        self._username = config.get('username')
        self._password = config.get('password')
        self._recordcount = config.get('records count')

        if hasattr(Vault, 'get_vault_tmp_dir'):
            temp_dir = Vault.get_vault_tmp_dir()
        else:
            temp_dir = "/opt/phantom/vault/tmp/"

        self._tmp_pem_file = tempfile.NamedTemporaryFile(dir=temp_dir, mode='w+b', delete=False)
        self._tmp_pem_file.write(config.get('PEM key'))
        self._key_tmp_name = self._tmp_pem_file.name
        self._tmp_pem_file.close()
        os.path.exists(self._tmp_pem_file.name)

        return phantom.APP_SUCCESS

    def finalize(self):
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

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            login_url = KasperskyTIConnector._get_phantom_base_url() + '/login'

            print ("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print ("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = KasperskyTIConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
