# File: bitglass_connector.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
try:
    import phantom.app as phantom
    from phantom.base_connector import BaseConnector
    from phantom.action_result import ActionResult
    underphantom = True
except ImportError:
    underphantom = False
    from test.actions import phantom, BaseConnector, ActionResult


import os
import requests
import json
from datetime import datetime
import re
from bs4 import BeautifulSoup

from app.bg import bitglassapi as bgapi

from bitglass_consts import *


conf = None


def find_char_nth(string, char, n):
    """Find the n'th occurrence of a character within a string."""
    return [i for i, c in enumerate(string) if c == char][n - 1]


def get_base_url(api_url):
    n = find_char_nth(api_url, '/', 2)
    if '/' in api_url[n + 1:]:
        return api_url[:find_char_nth(api_url, '/', 3)]
    else:
        return api_url


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class PatternMatch(object):
    def __init__(self, username, pattern, time, data={}, field='email'):
        self.username = username
        self.pattern = pattern
        self.time = time
        self.data = data
        self.field = field

        # Set the additional cef field
        self.data['userName'] = username
        self.data['dataPatterns'] = pattern


class BitglassConnector(BaseConnector):
    def __init__(self):

        # Call the BaseConnectors init first
        super(BitglassConnector, self).__init__()

        self._state = None

        self.datapath = None

        # Accumulate the users to add to the risky group
        self.newUsers = []
        self.newMatches = []

        # Cash the added ones to cut down on extra API calls (assuming none of the users
        # were removed from the group by another app / manually)
        self.riskyUsers = []

    # NOTE The phantom wizard code supports the requests lib only, not urllib
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
                    error_code, error_msg)
        except:
            self.debug_print("Error occurred while parsing the error message")
            error_text = PARSE_ERR_MSG

        return error_text

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

            # NOTE Don't treat html unconditionally as error (as the wizard does)
            if 200 <= status_code < 399:
                return RetVal(phantom.APP_SUCCESS, error_text)
        except Exception as ex:
            err_msg = self._get_error_message_from_exception(ex)
            error_text = "Cannot parse error details: {0}".format(err_msg)

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as ex:
            err_msg = self._get_error_message_from_exception(ex)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(err_msg)
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
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, url, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        resp_json = None

        try:
            resp_json, r = bgapi().RestCall(endpoint, kwargs['params'])
        except requests.exceptions.ConnectionError:
            err_msg = 'Error Details: Connection Refused from the Server'
            return RetVal(action_result.set_status(phantom.APP_ERROR, err_msg), resp_json)
        except Exception as ex:
            err_msg = self._get_error_message_from_exception(ex)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(err_msg)
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _callBitglassApi(self, action_result, _type, action, param, params):
        if params:
            # Make rest call
            url, endpoint = bgapi().RestParamsConfig(None, '1', _type, action)
            ret_val, response = self._make_rest_call(url, endpoint, action_result, params=params, headers=None)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            # Add JSON data
            action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # This code is similar to on_poll() with overriding logtypes with cloudsummary and all the data descarded

        # HACK Skip the actual API call to poll by setting APP_SUCCESS if needed
        ret_val, _ = RetVal(action_result.set_status(phantom.APP_ERROR), {})
        if phantom.is_fail(ret_val):
            # Multiple rest requests below, each one containing multiple log events
            try:
                status = bgapi(self).PollLogs(conf, [u'cloudsummary'])
                ret_val, _ = RetVal(
                    action_result.set_status(
                        phantom.APP_SUCCESS if status['last'].ok() else phantom.APP_ERROR),
                    status['last'].lastRes.json() if status['last'].ok() else None)
            except Exception as ex:
                err_msg = self._get_error_message_from_exception(ex)
                return action_result.set_status(phantom.APP_ERROR, err_msg)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def bgPushLogEvent(self, d, address, logTime):
        user = None
        try:
            if d[u'logtype'] == 'access':
                # TODO ?? Why ALL-PCI not matching with 'PCI.*' (without ^)?
                if re.fullmatch(conf.filter_access, d[u'dlppattern']):
                    self.debug_print('access matched', d[u'dlppattern'])
                    user = d[u'email']
                    pattern = d[u'dlppattern']
                    field = 'email'
            elif d[u'logtype'] == 'cloudaudit':
                if re.fullmatch(conf.filter_cloudaudit, d[u'patterns']):
                    self.debug_print('cloudaudit matched', d[u'patterns'])
                    user = d[u'owner']
                    pattern = d[u'patterns']
                    field = 'owner'
        except Exception:
            pass

        if user:
            # Add all matches properly, not just first matches for the user
            if user not in self.newUsers:
                self.newUsers.append(user)
            self.newMatches.append(PatternMatch(user, pattern, d[u'time'], d, field))

    def bgFlushLogEvents(self):
        # A new container is created in _save_new_container
        pass

    def _save_new_container(self, action_result, artifacts, key=GC_ALERT_USER_MATCH_KEY):
        container = {
            'name': '{0} {1}'.format(key, datetime.utcnow().strftime(GC_DATE_FORMAT)),
            'artifacts': [{
                'name': '{0}: {1}'.format(u.field.title(), u.username),
                'label': 'User Alert Artifact',
                'data': u.data,
                'source_data_identifier': '{0}_{1}'.format(u.username, u.time),
                # TODO ?? Limit to a subset of the full data?
                'cef': u.data,
                "cef_types": {
                    u.field: GC_BG_USERNAME_CONTAINS,
                    'userName': GC_BG_USERNAME_CONTAINS,

                    # TODO Find the type to use for DLP patterns field etc.
                    # 'dataPatterns': GC_BG_PATTERN_CONTAINS,
                },

                    } for u in artifacts]
        }

        # Don't add empty containers
        res, msg, cid = (phantom.APP_SUCCESS, 'No new artifacts found.', 0)
        if len(container['artifacts']) > 0:
            res, msg, cid = self.save_container(container)
            self.debug_print(
                "Save_container (with artifacts) returns, value: {0}, reason: {1}, id: {2}".format(res, msg, cid))

            # Reset the users pool just added (just in case as the connector object dies anyways)
            if underphantom and not phantom.is_fail(res):
                self.newUsers = []
                self.newMatches = []

        return res, msg, cid

    def _print_debug(self, msg):
        """ Use this for testing if the logging is broken/disabled
        """
        # Create a randomly named file here and print to it
        from app.config import tempfile
        mode = 'w+'
        with tempfile(conf._folder, mode=mode) as tmppath:
            with open(tmppath, mode=mode) as file:
                print(msg, file=file)
            os.rename(tmppath, tmppath + '_')

    def _handle_on_poll(self, param):
        """ NOTE The action name 'on_poll' is magic and makes the 'Ingest Settings' tab appear in the asset settings
        """

        # self._print_debug('_handle_on_poll')

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # No usable params defined, they are supplied by asset
        # param['xyz']

        # HACK Skip the actual API call to poll by setting APP_SUCCESS if needed
        ret_val, _ = RetVal(action_result.set_status(phantom.APP_ERROR), {})
        if phantom.is_fail(ret_val):
            # Multiple rest requests below, each one containing multiple log events
            status = bgapi(self).PollLogs(conf)
            ret_val, _ = RetVal(
                action_result.set_status(
                    phantom.APP_SUCCESS if status['last'].ok() else phantom.APP_ERROR),
                # NOTE An empty data set is returned (drained). Also see comments below
                status['last'].lastRes.json() if status['last'].ok() else None)

        # Even if an error returned, treat it as successful as long as at least one rest call was successful
        # (as would be reflected in lastlog.json) to avoid losing any data
        res, msg, cid = self._save_new_container(action_result, self.newMatches)
        self.save_progress("Save_container (with artifacts) returns, value: {0}, reason: {1}, id: {2}".format(res, msg, cid))

        if phantom.is_fail(ret_val):
            if cid == 0:
                return action_result.get_status()
            else:
                # Some (one or more requests) data was received but it failed in a subsequent request
                # Return success for consistency. The data failed being retrieved will be retrieved later
                return action_result.set_status(phantom.APP_SUCCESS)

        # This would contain empty data (the last empty request) as a side effect of logeventdaemon implementation
        # and BG API not having 'data done' hint so ending up with empty data set in the last successful request
        # Fortunately, we don't care as it doesn't look like using this under polling is needed
        # action_result.add_data(response)

        # It seems the following (?? why multiple objects) are set automatically, no need to add:
        # summary.total_objects
        # summary.total_objects_successful

        # Return summary? - Not for polling ingestion!
        # summary = action_result.update_summary(msg)

        # Return success, no need to set the message, only the status
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_artifact_cef(self, id):

        url = '{0}rest/artifact/{1}/'.format(self.get_phantom_base_url(), id)

        try:
            r = requests.get(url, verify=conf.verify_local)
            cef = r.json()['cef']
        except Exception as ex:
            err_msg = self._get_error_message_from_exception(ex)
            self.debug_print("Unable to query Bitglass artifact: {}".format(err_msg))
            return None

        return cef

    def _handle_filter_by_dlp_pattern(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get data
        matchRe = param['bg_match_expression']
        aid = param['bg_log_event']

        cef = self._get_artifact_cef(aid)
        if cef:
            try:
                if re.fullmatch(matchRe, cef['dataPatterns']):
                    self.debug_print("'dataPatterns' matched", cef['dataPatterns'])
                    action_result.add_data(cef)
                else:
                    # To avoid the error message, have to return non-empty set of data.
                    # This will be ignored as the user name is empty
                    cef['userName'] = '_'
                    action_result.add_data(cef)
            except Exception:
                self.debug_print("'dataPatterns' not found")

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully completed the action")

    def _handle_create_update_group(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        groupName = param['bg_group_name']
        newGroupName = param.get('bg_new_group_name', '')
        # Workaround W503
        try:
            params = json.loads(''.join([
                '{',
                '"groupname": "{0}"'.format(groupName),
                ', "newgroupname": ["{0}"]'.format(newGroupName) if newGroupName != '' else '',
                '}',
            ]))
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, INVALID_PARAMS_ERR_MSG)

        return self._callBitglassApi(action_result, 'group', 'createupdate', param, params)

    def _handle_delete_group(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        groupName = param['bg_group_name']
        try:
            params = json.loads(''.join([
                '{',
                '"groupname": "{0}"'.format(groupName),
                '}',
            ]))
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, INVALID_PARAM_ERR_MSG)

        return self._callBitglassApi(action_result, 'group', 'delete', param, params)

    def _handle_add_user_to_group(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        groupName = param['bg_group_name']
        userName = param['bg_user_name']

        haveUserName = True
        if underphantom:
            # newUsers is preserved between actions ONLY in testing (separate app instances in the former)
            if userName != '' and userName != '_':
                self.newUsers = [userName]
            else:
                haveUserName = False

        params = None
        try:
            if haveUserName:
                params = json.loads(''.join([
                    '{',
                    '"groupname": "{0}", "companyemail": [{1}]'.format(groupName,
                                                                    ','.join(['"' + u + '"'
                                                                            for u in self.newUsers])),
                    '}',
                ]))
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, INVALID_PARAMS_ERR_MSG)

        return self._callBitglassApi(action_result, 'group', 'addmembers', param, params)

    def _handle_remove_user_from_group(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        groupName = param['bg_group_name']
        userName = param['bg_user_name']

        haveUserName = True
        if underphantom:
            # newUsers is preserved between actions ONLY in testing (separate app instances in the former)
            if userName == '':
                haveUserName = False

        params = None
        if haveUserName:
            try:
                params = json.loads(''.join([
                    '{',
                    '"groupname": "{0}", "companyemail": [{1}]'.format(groupName,
                                                                    ','.join(['"' + u + '"'
                                                                                for u in [userName]])),
                    '}',
                ]))
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, INVALID_PARAMS_ERR_MSG)

        return self._callBitglassApi(action_result, 'group', 'removemembers', param, params)

    def _handle_create_update_user(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        userName = param['bg_user_name']

        firstName = param.get('bg_first_name', '')
        lastName = param.get('bg_last_name', '')
        secondaryEmail = param.get('bg_secondary_email', '')
        netbiosDomain = param.get('bg_netbios_domain', '')
        samAccountName = param.get('bg_sam_account_name', '')
        userPrincipalName = param.get('bg_user_principal_name', '')
        objectGuid = param.get('bg_object_guid', '')
        countryCode = param.get('bg_country_code', '')
        mobileNumber = param.get('bg_mobile_number', '')
        adminRole = param.get('bg_admin_role', '')
        groupMembership = param.get('bg_group_membership', '')

        try:
            params = json.loads(''.join([
                '{',
                '"companyemail": "{0}"'.format(userName),
                ', "firstname": ["{0}"]'.format(firstName) if firstName != '' else '',
                ', "lastname": "{0}"'.format(lastName) if lastName != '' else '',
                ', "secondaryemail": "{0}"'.format(secondaryEmail) if secondaryEmail != '' else '',
                ', "netbiosdomain": "{0}"'.format(netbiosDomain) if netbiosDomain != '' else '',
                ', "samaccountname": "{0}"'.format(samAccountName) if samAccountName != '' else '',
                ', "userprincipalname": "{0}"'.format(userPrincipalName) if userPrincipalName != '' else '',
                ', "objectguid": "{0}"'.format(objectGuid) if objectGuid != '' else '',
                ', "countrycode": "{0}"'.format(countryCode) if countryCode != '' else '',
                ', "mobilenumber": "{0}"'.format(mobileNumber) if mobileNumber != '' else '',
                ', "adminrole": "{0}"'.format(adminRole) if adminRole != '' else '',
                # Support just one group for now
                ', "groupmembership": ["{0}"]'.format(groupMembership) if groupMembership != '' else '',
                '}',
            ]))
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, INVALID_PARAMS_ERR_MSG)

        return self._callBitglassApi(action_result, 'user', 'createupdate', param, params)

    def _handle_deactivate_user(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        userName = param['bg_user_name']

        try:
            params = json.loads(''.join([
                '{',
                '"companyemail": "{0}"'.format(userName),
                '}',
            ]))
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, INVALID_PARAM_ERR_MSG)

        return self._callBitglassApi(action_result, 'user', 'deactivate', param, params)

    def _handle_reactivate_user(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        userName = param['bg_user_name']

        try:
            params = json.loads(''.join([
                '{',
                '"companyemail": "{0}"'.format(userName),
                '}',
            ]))
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, INVALID_PARAM_ERR_MSG)

        return self._callBitglassApi(action_result, 'user', 'reactivate', param, params)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", action_id)
        self.save_progress("In action handler for: {0}".format(action_id))

        if 'test_connectivity' in action_id:
            ret_val = self._handle_test_connectivity(param)

        elif 'on_poll' in action_id:
            ret_val = self._handle_on_poll(param)

        elif 'filter_by_dlp_pattern' in action_id:
            ret_val = self._handle_filter_by_dlp_pattern(param)

        elif 'create_update_group' in action_id:
            ret_val = self._handle_create_update_group(param)

        elif 'delete_group' in action_id:
            ret_val = self._handle_delete_group(param)

        elif 'add_user_to_group' in action_id:
            ret_val = self._handle_add_user_to_group(param)

        elif 'remove_user_from_group' in action_id:
            ret_val = self._handle_remove_user_from_group(param)

        elif 'create_update_user' in action_id:
            ret_val = self._handle_create_update_user(param)

        elif 'deactivate_user' in action_id:
            ret_val = self._handle_deactivate_user(param)

        elif 'reactivate_user' in action_id:
            ret_val = self._handle_reactivate_user(param)

        return ret_val

    def bgLoadConfig(self, conf):
        # get the asset config
        config = self.get_config()

        # Not used in Phantom as it manages polling by itself
        # conf.log_interval = config['log_interval']

        conf.api_url = config['api_url']

        conf.verify = config.get('verify_server_cert', False)

        # Need to keep False for dev but avoiding security code scan flags by using this variable
        # TODO This is borrowed from external API settings but we need this local one separately set??
        #      Is this some Phantom instance setting which (valid or self-signed) cert to use??
        #      Check if verify=True works for local APIs in the currently used instance
        conf.verify_local = conf.verify

        # TODO Don't know how to custom validate asset fields so have to do it here
        try:
            conf.proxies = conf._getProxies(config.get('proxies', ''))
        except BaseException as ex:
            err_msg = self._get_error_message_from_exception(ex)
            self.debug_print('Bad proxy param while getting configuration params {}'.format(err_msg))

        # These 2 are extra
        conf.filter_access = config.get('filter_access', '')
        conf.filter_cloudaudit = config.get('filter_cloudaudit', '')

        # Access and CloudAudit only, if enabled and non-empty pattern expression only
        # (the latter is to avoid accidental flooding with unnecessary high frequency data)
        conf.log_types = []
        if config['enable_access'] and conf.filter_access != '':
            conf.log_types += [u'access']
        if config['enable_cloudaudit'] and conf.filter_cloudaudit != '':
            conf.log_types += [u'cloudaudit']

        # Secret parameters are not loaded in either mode
        conf._auth_token.pswd = config['auth_token']

        conf._username = config.get('username', '')
        conf._password.pswd = config.get('password', '')

    def initialize(self):

        global conf

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # TODO  self.datapath would be None as the rule is executed separately! So default for
        #       the same (well-defined, without uuids) path for now.. The uuid is available in bitglass.json as appid
        # Do not parse command line params on a real Phantom instance as it has custom Python runtime (missing sys.argv)
        conf = bgapi(self).Initialize(self.datapath, skipArgs=True)

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    # import pudb
    # pudb.set_trace()

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
            # TODO ?? Implement _get_phantom_base_url()
            login_url = BitglassConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            # TODO Switched to verify=True for the sake of the security scan, no config yet parsed by now..
            #      Add command option?
            r = requests.get(login_url, verify=True)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            # TODO Switched to verify=True for the sake of the security scan, no config yet parsed by now..
            #      Add command option?
            r2 = requests.post(login_url, verify=True, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = BitglassConnector()

        # NOTE This doesn't work, it's called in separate processes it seems (((
        # connector.datapath = os.path.split(args.input_test_json)[0] + os.sep

        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(str(ret_val)), indent=4))

        if not underphantom:
            connector._runAllActions()

    exit(0)


if __name__ == '__main__':
    main()
