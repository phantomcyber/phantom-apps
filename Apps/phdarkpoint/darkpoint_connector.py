# File: darkpoint_connector.py
# Copyright (c) 2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
try:
    from phantom.vault import Vault
except:
    import phantom.vault as Vault

import requests
import json
import time
from darkpoint_consts import *
from bs4 import BeautifulSoup
from darkpointrest.darkpoint import Darkpoint, AuthenticationError, ValidationError
from darkpointrest.exceptions import DarkpointRESTException


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class DarkpointConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(DarkpointConnector, self).__init__()

        self._state = None

    def _init_darkpoint_client(self, action_result):
        try:
            dp_client = Darkpoint(
                user=self._username,
                password=self._password,
                host=self._base_url
            )
            # need to call the keep alive or certain APIs will return blank
            dp_client.cookie_keep_alive()

            return RetVal(phantom.APP_SUCCESS, dp_client)
        except AuthenticationError as aerr:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error authenticating with DarkPoint service. Details: {0}".format(str(aerr))), None)
        except Exception as aerr:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error while connecting to the server. Details: {0}".format(str(aerr))), None)

    def _get_vault_payload(self, param, action_result):
        vault_id = param['vault_id']
        try:
            if hasattr(Vault, 'get_file_path'):
                payload = open(Vault.get_file_path(vault_id), 'rb')
            else:
                payload = open(Vault.get_vault_file(vault_id), 'rb')
        except:
            return (action_result.set_status(phantom.APP_ERROR, ('File not found in vault ("{}")').format(vault_id)), None)

        return (phantom.APP_SUCCESS, payload)

    def _get_vault_file_sha1(self, vault_id, action_result):
        self.save_progress('Getting the sha1 of the file')
        sha1 = None
        metadata = None
        if hasattr(Vault, 'get_file_info'):
            try:
                metadata = Vault.get_file_info(container_id=self.get_container_id(), vault_id=vault_id)[0]['metadata']
            except Exception as e:
                self.debug_print('Handled Exception:', e)
                metadata = None

        else:
            try:
                metadata = Vault.get_meta_by_hash(self.get_container_id(), vault_id, calculate=True)[0]
            except:
                self.debug_print('Handled Exception:', e)
                metadata = None

        if not metadata:
            return (action_result.set_status(phantom.APP_ERROR, 'Unable to get meta info of vault file'), None)
        try:
            sha1 = metadata['sha1']
        except Exception as e:
            self.debug_print('Handled exception', e)
            return (
             action_result.set_status(phantom.APP_ERROR, 'Unable to get meta info of vault file'), None)

        return (phantom.APP_SUCCESS, sha1)

    def _process_empty_reponse(self, response, action_result):

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

        message = message.replace('{', '{{').replace('}', '}}')

        if len(message) > 500:
            message = " error while connecting to the server"

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
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

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

        # Process an HTML resonse, Do this no matter what the api talks.
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
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get"):

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                            url,
                            data=data,
                            headers=headers,
                            verify=config.get('verify_server_cert', False),
                            params=params)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _check_detonated_report(self, sha1, action_result):
        ret_val, dp_client = self._init_darkpoint_client(action_result)

        if phantom.is_fail(ret_val):
            return RetVal(action_result.get_status(), None)

        try:
            detonation_report = dp_client.artifact.get_artifact_entries(sha1s=[sha1])
            if isinstance(detonation_report, list):
                if len(detonation_report) > 0:
                    detonation_report = detonation_report[0]
                else:
                    return RetVal(action_result.set_status(phantom.APP_ERROR, 'No artifacts found'), None)
            else:
                return RetVal(action_result.set_status(phantom.APP_ERROR, 'No artifacts found'), None)
        except DarkpointRESTException as dpre:
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Error encountered while retrieving artifact entries.\r\n{0}'.format(dpre)), None)

        return (phantom.APP_SUCCESS, detonation_report)

    def _poll_task_status(self, action_result, sha1):
        ret_val, dp_client = self._init_darkpoint_client(action_result)
        if phantom.is_fail(ret_val):
            return RetVal(action_result.get_status(), None)

        polling_attempt = 0
        max_polling_attempts = int(self._detonate_timeout) * 60 / DARKPOINT_SLEEP_SECS

        while polling_attempt < max_polling_attempts:
            polling_attempt += 1
            self.save_progress(('Polling attempt {0} of {1}').format(polling_attempt, max_polling_attempts))
            try:
                status = dp_client.workflow.status(users=[self._username], sha1s=[sha1])
            except Exception as e:
                return (action_result.set_status(phantom.APP_ERROR,
                            "Error occurred while fetching the workflow status of the user: {0} and SHA1 hash: {1}. Error: {2}".format(self._username, sha1, str(e))), None)
            estimated_artifacts_queued = status['count']
            if estimated_artifacts_queued == 0:
                ret_val, response = self._check_detonated_report(sha1, action_result)
                if phantom.is_fail(ret_val):
                    return (action_result.get_status(), None)

                return (action_result.set_status(phantom.APP_SUCCESS), response)

            time.sleep(DARKPOINT_SLEEP_SECS)

        return (
         action_result.set_status(phantom.APP_ERROR, DARKPOINT_MSG_MAX_POLLS_REACHED), None)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to DarkPoint service...")
        ret_val, dp_client = self._init_darkpoint_client(action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        # Retrieve artifact SHA1s to test connectivity
        try:
            self.save_progress("Retrieving SHA1s for artifacts associated with this user...")
            dp_client.artifact.get_sha1s()
        except DarkpointRESTException as dpre:
            return action_result.set_status(phantom.APP_ERROR, 'Error encountered while retrieving artifact SHA1s.\r\n{0}'.format(dpre))
        except ValidationError as verr:
            return action_result.set_status(phantom.APP_ERROR, 'ValidationError encountered while retrieving artifact SHA1s.\r\n{0}'.format(verr))

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_detonate_file(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, vault_file = self._get_vault_payload(param, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        vault_id = param['vault_id']
        ret_val, sha1 = self._get_vault_file_sha1(vault_id, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        data = action_result.add_data({})

        # connect client to DarkPoint service
        ret_val, dp_client = self._init_darkpoint_client(action_result)
        if phantom.is_fail(ret_val):
            return RetVal(action_result.get_status(), None)

        # check for prior detonations
        self.save_progress('Checking for prior detonations')
        ret_val, response = self._check_detonated_report(sha1, action_result)

        # if no priors, detonate now
        if phantom.is_fail(ret_val):
            self.save_progress('Uploading the file')
            try:
                dp_client.artifact.upload(param.get('filename', sha1), data=vault_file)
            except Exception as e:
                action_result.set_status(phantom.APP_ERROR,
                                        "Error while uploading the file: {0}. Error: {1}".format(param.get('filename', sha1), str(e)))

            if phantom.is_fail(ret_val):
                return self.get_status()

            ret_val, response = self._poll_task_status(action_result, sha1)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        action_result.update_summary({
            'darkpointScore': response.get('analysis', {}).get('darkpointScore', 0)
        })
        response['report'] = response.get('analysis', {})
        try:
            del response['analysis']
        except KeyError:
            pass
        data.update(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_detonate_url(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # connect client to DarkPoint service
        ret_val, dp_client = self._init_darkpoint_client(action_result)
        if phantom.is_fail(ret_val):
            return RetVal(action_result.get_status(), None)

        url = param['url']

        headers = {
                'darkpoint-source': 'python/restclient',
                'Cookie': dp_client.auth_cookie,
                'Content-Type': 'application/json'
        }

        data = json.dumps({
            'urls': [url],
            'hunter': 'Python REST Client'
        })

        ret_val, response = self._make_rest_call(
                '/api/auth/artifact/url',
                action_result,
                headers=headers,
                data=data,
                method='post'
        )

        # grab sha1 from response
        try:
            sha1 = response['sha1']
        except KeyError:
            sha1 = response.get(url, {}).get('sha1', '')

        if not len(sha1):
            return action_result.set_status(phantom.APP_ERROR,
                'Error when sending URL to Darkpoint service:\r\n{0}'.format(str(response)))

        # check status
        ret_val, response = self._poll_task_status(action_result, sha1)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # grab URL analysis
        try:
            url_analysis = dp_client.artifact.get_artifact_entries(sha1s=[sha1], sections=['URLAnalyzer'])
            url_analysis = url_analysis.get('URLAnalyzer', {})
            url_analysis = json.loads(url_analysis).get('analysis')
        except Exception:
            url_analysis = {}

        data = action_result.add_data({})
        data.update({'analysis': url_analysis})

        action_result.update_summary({
            'darkpointScore': response.get('analysis', {}).get('darkpointScore', 0)
        })
        response['report'] = response.get('analysis', {})
        try:
            del response['analysis']
        except KeyError:
            pass
        data.update(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_report(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # the report ID should just be the SHA1
        report_id = param['id']

        data = action_result.add_data({})

        # connect client to DarkPoint service
        ret_val, dp_client = self._init_darkpoint_client(action_result)
        if phantom.is_fail(ret_val):
            return RetVal(action_result.get_status(), None)

        # check for prior detonations
        self.save_progress('Retrieving detonation report')
        ret_val, response = self._check_detonated_report(report_id, action_result)

        # if no report, return
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.update_summary({
            'darkpointScore': response.get('analysis', {}).get('darkpointScore', 0)
        })
        response['report'] = response.get('analysis', {})
        try:
            del response['analysis']
        except KeyError:
            pass
        data.update(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'detonate_file':
            ret_val = self._handle_detonate_file(param)

        elif action_id == 'detonate_url':
            ret_val = self._handle_detonate_url(param)

        elif action_id == 'get_report':
            ret_val = self._handle_get_report(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._base_url = config['base_url']
        if self._base_url.endswith('/'):
            self._base_url = self._base_url[0:-1]

        self._username = config['username']
        self._password = config['password']
        self._detonate_timeout = config.get('detonate_timeout', 10)

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
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
            login_url = BaseConnector._get_phantom_base_url() + "login"
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
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = DarkpointConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
