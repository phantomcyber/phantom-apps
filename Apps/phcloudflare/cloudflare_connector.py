# File: cloudflare_connector.py
#
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from cloudflare_consts import *
import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class CloudflareConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(CloudflareConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Status code: {}. Empty response and no information in the header".format(response.status_code)
            ), None
        )

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
                    error_code = CLOUDFLARE_ERR_CODE_MSG
                    error_msg = e.args[0]
            else:
                error_code = CLOUDFLARE_ERR_CODE_MSG
                error_msg = CLOUDFLARE_ERR_MSG_UNAVAILABLE
        except:
            error_code = CLOUDFLARE_ERR_CODE_MSG
            error_msg = CLOUDFLARE_ERR_MSG_UNAVAILABLE

        try:
            if error_code in CLOUDFLARE_ERR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(
                    error_code, error_msg)
        except:
            self.debug_print("Error occurred while parsing the error message")
            error_text = CLOUDFLARE_PARSE_ERR_MSG

        return error_text

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(
            status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. {0}".format(err)
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

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), resp_json)

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
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = "{}{}".format(self._base_url, endpoint)

        try:
            r = request_func(
                url,
                verify=config.get('verify_server_cert', False),
                **kwargs
            )
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. {0}".format(err)
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, response = self._make_rest_call(
            CLOUDFLARE_ZONES_ENDPOINT, action_result, params=None, headers=self._headers
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_zoneid(self, action_result, zone_name):
        self.save_progress("Fetching zone for domain '{}'".format(zone_name))

        parameters = {
            'name': zone_name
        }

        ret_val, response = self._make_rest_call(
            CLOUDFLARE_ZONES_ENDPOINT, action_result, params=parameters,
            headers=self._headers
        )

        if phantom.is_fail(ret_val):
            return RetVal(action_result.set_status(phantom.APP_ERROR, action_result.get_message()), None)

        # Analyze unique response
        try:
            result = response['result'][0]
            zone_id = result['id']
            msg = "Successfully retrieved zone id '{}' from domain '{}'".format(zone_id, zone_name)
            return RetVal(action_result.set_status(phantom.APP_SUCCESS, msg), zone_id)
        except:
            return RetVal(action_result.set_status(phantom.APP_ERROR, CLOUDFLARE_PARSE_RESPONSE_ERR_MSG), None)

    def _update_fw_rule(self, action_result, zone_id, payload):
        fw_rule_id = payload['id']
        paused = payload['paused']

        self.save_progress("Updating Firewall Rule {}".format(fw_rule_id))

        ret_val, response = self._make_rest_call(
            CLOUDFLARE_FWRULE_ENDPOINT.format(zone_id=zone_id), action_result, method='put',
            data=json.dumps([payload]), headers=self._headers
        )

        if phantom.is_fail(ret_val):
            return RetVal(action_result.set_status(phantom.APP_ERROR, action_result.get_message()), None)

        msg = "Successfully {} firewall rule {}".format(
            "enabled" if not paused else "disabled", fw_rule_id)
        return RetVal(action_result.set_status(phantom.APP_SUCCESS, msg), response)

    def _create_filter(self, action_result, zone_id, payload):
        self.save_progress("Creating Filter Rule")

        # Create a filter matching that ip / user-agent / other
        ret_val, response = self._make_rest_call(
            CLOUDFLARE_FILTERS_ENDPOINT.format(zone_id=zone_id), action_result, method='post',
            data=json.dumps(payload), headers=self._headers
        )
        try:
            if phantom.is_fail(ret_val):
                err = response['errors'][0]
                if 'code' not in err:
                    return RetVal(action_result.set_status(phantom.APP_ERROR, action_result.get_message()), None)

                if err['code'] != CLOUDFLARE_DUPLICATES_ERRCODE:
                    return RetVal(action_result.set_status(phantom.APP_ERROR, action_result.get_message()), None)

                filter_id = err['meta']['id']
                msg = "Filter {} already existing".format(filter_id)
            else:
                # Created
                result = response['result'][0]
                filter_id = result['id']
                msg = "Successfully created filter {}".format(filter_id)
                return RetVal(action_result.set_status(phantom.APP_SUCCESS, msg), filter_id)
        except:
            return RetVal(action_result.set_status(phantom.APP_ERROR, CLOUDFLARE_PARSE_RESPONSE_ERR_MSG), None)

    def _handle_block_ip(self, param):
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        ip = param['ip']
        domain_name = param['domain_name']
        rule_name = param.get('rule_descr', 'Phantom Block IP')

        # Get Zone Identifier from Zone (Domain) Name
        ret_val, response = self._get_zoneid(action_result, domain_name)
        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            return action_result.get_status()

        self.save_progress(action_result.get_message())
        zid = response

        payload = [{
            "expression": CLOUDFLARE_FILTER_RULE_IP.format(ip=ip)
        }]

        # Create a filter matching that ip
        ret_val, response = self._create_filter(action_result, zid, payload)
        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            return action_result.get_status()

        self.save_progress(action_result.get_message())
        filter_id = response

        # Create a rule using that filter
        self.save_progress("Creating Firewall Rule")

        payload = {
            "filter": {
                "id": filter_id
            },
            "action": "block",
            "description": rule_name,
            "paused": False
        }

        ret_val, response = self._make_rest_call(
            CLOUDFLARE_FWRULE_ENDPOINT.format(zone_id=zid), action_result, method='post',
            data=json.dumps([payload]), headers=self._headers
        )
        try:
            if phantom.is_fail(ret_val):
                err = response['errors'][0]
                if 'code' not in err:
                    self.save_progress(action_result.get_message())
                    return action_result.get_status()

                if err['code'] != CLOUDFLARE_DUPLICATES_ERRCODE:
                    self.save_progress(action_result.get_message())
                    return action_result.get_status()

                rule_id = err['meta']['id']
                self.save_progress(
                    "Firewall Rule {} already existing".format(rule_id))

                # Updating existing rule!
                payload['id'] = rule_id
                # NOTE this operation will also overwrite description and any other eventual param
                ret_val, response = self._update_fw_rule(
                    action_result, zid, payload)
                if phantom.is_fail(ret_val):
                    self.save_progress(action_result.get_message())
                    return action_result.get_status()

                self.save_progress(action_result.get_message())

            else:
                # Created
                result = response['result'][0]
                rule_id = result['id']
                self.save_progress(
                    "Successfully created firewall rule {}".format(rule_id))
                return action_result.set_status(phantom.APP_SUCCESS)
        except:
            return action_result.set_status(phantom.APP_ERROR, CLOUDFLARE_PARSE_RESPONSE_ERR_MSG)

    def _handle_update_rule(self, param):
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        rule_name = param['rule_name']
        domain_name = param['domain_name']
        action = param['action']

        # Safety check on action parameter
        if action not in CLOUDFLARE_VALID_ACTIONS.keys():
            return action_result.set_status(phantom.APP_ERROR, status_message=CLOUDFLARE_INVALID_ACTION_ERR.format(action=action))

        # Get Zone Identifier from Zone (Domain) Name
        ret_val, response = self._get_zoneid(action_result, domain_name)
        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            return action_result.get_status()

        self.save_progress(action_result.get_message())
        zid = response

        parameters = {
            "description": rule_name
        }

        # Get individual firewall rule
        ret_val, response = self._make_rest_call(
            CLOUDFLARE_FWRULE_ENDPOINT.format(zone_id=zid), action_result,
            params=parameters, headers=self._headers
        )

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            return action_result.get_status()

        # Edit returned fw rule (assuming unique)
        try:
            payload = response['result'][0]
        except:
            return action_result.set_status(phantom.APP_ERROR, CLOUDFLARE_PARSE_RESPONSE_ERR_MSG)
        # payload['action'] = 'block'
        payload['paused'] = CLOUDFLARE_VALID_ACTIONS[action]

        # Enable / disable rule depending on action value
        # No need to change action itself.
        self.debug_print("{} Firewall Rule {}".format(
            "Enabling" if payload['paused'] else "Disabling", payload['id']))

        ret_val, response = self._update_fw_rule(action_result, zid, payload)
        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            return action_result.get_status()

        self.save_progress(action_result.get_message())

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_block_useragent(self, param):
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        user_agent = param['user_agent']
        domain_name = param['domain_name']
        rule_name = param.get('rule_descr', 'Phantom Block UserAgent')

        # Get Zone Identifier from Zone (Domain) Name
        ret_val, response = self._get_zoneid(action_result, domain_name)
        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            return action_result.get_status()

        self.save_progress(action_result.get_message())
        zid = response

        payload = [{
            "expression": CLOUDFLARE_FILTER_RULE_UA.format(ua=user_agent)
        }]

        # Create a filter matching that user-agent
        ret_val, response = self._create_filter(action_result, zid, payload)
        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            return action_result.get_status()

        self.save_progress(action_result.get_message())
        filter_id = response

        # Create a rule using that filter
        self.save_progress("Creating Firewall Rule")

        payload = {
            "filter": {
                "id": filter_id
            },
            "action": "block",
            "description": rule_name,
            "paused": False
        }

        ret_val, response = self._make_rest_call(
            CLOUDFLARE_FWRULE_ENDPOINT.format(zone_id=zid), action_result, method='post',
            data=json.dumps([payload]), headers=self._headers
        )
        try:
            if phantom.is_fail(ret_val):
                err = response['errors'][0]
                if 'code' not in err:
                    self.save_progress(action_result.get_message())
                    return action_result.get_status()

                if err['code'] != CLOUDFLARE_DUPLICATES_ERRCODE:
                    self.save_progress(action_result.get_message())
                    return action_result.get_status()

                rule_id = err['meta']['id']
                self.save_progress(
                    "Firewall Rule {} already existing".format(rule_id))

                # Updating existing rule!
                payload['id'] = rule_id
                # NOTE this operation will also overwrite description and any other param if not provided
                ret_val, response = self._update_fw_rule(
                    action_result, zid, payload)
                if phantom.is_fail(ret_val):
                    self.save_progress(action_result.get_message())
                    return action_result.get_status()

                self.save_progress(action_result.get_message())

            else:
                # Created
                result = response['result'][0]
                rule_id = result['id']
                self.save_progress(
                    "Successfully created firewall rule {}".format(rule_id))
                return action_result.set_status(phantom.APP_SUCCESS)
        except:
            return action_result.set_status(phantom.APP_ERROR, CLOUDFLARE_PARSE_RESPONSE_ERR_MSG)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'block_ip':
            ret_val = self._handle_block_ip(param)

        elif action_id == 'update_rule':
            ret_val = self._handle_update_rule(param)

        elif action_id == 'block_useragent':
            ret_val = self._handle_block_useragent(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._base_url = config['base_url']

        if not self._base_url.endswith('/'):
            self._base_url += "/"

        self._headers = {
            "Authorization": "Bearer {}".format(config['api_token']),
            "Content-Type": "application/json"
        }

        return phantom.APP_SUCCESS

    def finalize(self):
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
            login_url = CloudflareConnector._get_phantom_base_url() + '/login'

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
            r2 = requests.post(login_url, verify=False,
                               data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CloudflareConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
