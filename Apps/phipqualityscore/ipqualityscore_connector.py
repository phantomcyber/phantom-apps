# File: ipqualityscore_connector.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Local imports
import ipqualityscore_consts

# Global imports
import simplejson as json
import requests
import time
import urllib.parse


class IpqualityscoreConnector(BaseConnector):
    ACTION_ID_URL_CHECKER = 'check_url'
    ACTION_ID_IP_REPUTATION = 'ip_reputation'
    ACTION_ID_EMAIL_VALIDATION = 'email_validation'

    def __init__(self):
        super(IpqualityscoreConnector, self).__init__()

    def handle_action(self, param):
        result = None
        action_id = self.get_action_identifier()
        if action_id == self.ACTION_ID_URL_CHECKER:
            result = self.check_url(param)
        elif action_id == self.ACTION_ID_IP_REPUTATION:
            result = self.ip_reputation(param)
        elif action_id == self.ACTION_ID_EMAIL_VALIDATION:
            result = self.email_validation(param)
        elif action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            result = self.test_asset_connectivity(param)
        return result

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
                    error_code = ipqualityscore_consts.ERR_CODE_MSG
                    error_msg = e.args[0]
            else:
                error_code = ipqualityscore_consts.ERR_CODE_MSG
                error_msg = ipqualityscore_consts.ERR_MSG_UNAVAILABLE
        except:
            error_code = ipqualityscore_consts.ERR_CODE_MSG
            error_msg = ipqualityscore_consts.ERR_MSG_UNAVAILABLE

        try:
            if error_code in ipqualityscore_consts.ERR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
        except:
            self.debug_print(ipqualityscore_consts.PARSE_ERR_MSG)
            error_text = ipqualityscore_consts.PARSE_ERR_MSG

        return error_text

    def _validate_integer(self, action_result, parameter, key):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, ipqualityscore_consts.VALID_INTEGER_MSG.format(key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, ipqualityscore_consts.VALID_INTEGER_MSG.format(key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, ipqualityscore_consts.NON_NEGATIVE_INTEGER_MSG.format(key)), None

        return phantom.APP_SUCCESS, parameter

    def test_asset_connectivity(self, param):
        config = self.get_config()
        app_key = config.get('apikey', None)
        self.save_progress(ipqualityscore_consts.IPQUALITYSCORE_MSG_CONNECTING)
        time.sleep(10)
        try:
            if app_key:
                response_code = requests.get(
                    ipqualityscore_consts.IPQUALITYSCORE_API_TEST.format(apikey=app_key)).status_code
        except Exception as e:
            self.debug_print('test_asset_connectivity: ', e)
            self.set_status(
                phantom.APP_ERROR,
                ipqualityscore_consts.IPQUALITYSCORE_ERR_CONNECTIVITY_TEST, e)
            self.append_to_message(
                ipqualityscore_consts.IPQUALITYSCORE_MSG_CHECK_CONNECTIVITY)
            return self.get_status()

        if response_code == 200:
            return self.set_status_save_progress(
                phantom.APP_SUCCESS,
                ipqualityscore_consts.IPQUALITYSCORE_SUCC_CONNECTIVITY_TEST)
        else:
            self.set_status(phantom.APP_ERROR,
                            ipqualityscore_consts.
                            IPQUALITYSCORE_SERVER_RETURNED_ERROR_CODE.
                            format(code=response_code))
            self.append_to_message(
                ipqualityscore_consts.IPQUALITYSCORE_MSG_CHECK_CONNECTIVITY)
            return self.get_status()

    def create_req_url(self, urltype, param, app_key):
        if urltype == "url":
            req_url = ipqualityscore_consts.IPQUALITYSCORE_API_URL_CHECKER.format(
                apikey=app_key, url=urllib.parse.quote_plus(param.get('url')))
        elif urltype == "ip":
            req_url = ipqualityscore_consts.IPQUALITYSCORE_API_IP_REPUTATION.format(
                apikey=app_key, ip=(param.get('ip')))
        elif urltype == "email":
            req_url = ipqualityscore_consts.IPQUALITYSCORE_API_EMAIL_VALIDATION.format(
                apikey=app_key, email=param.get('email'))
        else:
            req_url = ''
        # optional parameters
        optional_param = ''
        if param.get('strictness') is not None:
            optional_param = "{}&strictness={}".format(optional_param, param.get('strictness'))
        if param.get('user_agent') is not None:
            optional_param = "{}&user_agent={}".format(optional_param, param.get('user_agent'))
        if param.get('user_language') is not None:
            optional_param = "{}&user_language={}".format(optional_param, param.get('user_language'))
        if param.get('fast') is not None:
            optional_param = "{}&fast={}".format(optional_param, param.get('fast'))
        if param.get('mobile') is not None:
            optional_param = "{}&mobile={}".format(optional_param, param.get('mobile'))
        if param.get('allow_public_access_points') is not None:
            optional_param = "{}&allow_public_access_points={}".format(optional_param, param.get('allow_public_access_points'))
        if param.get('lighter_penalties') is not None:
            optional_param = "{}&lighter_penalties={}".format(optional_param, param.get('lighter_penalties'))
        if param.get('transaction_strictness') is not None:
            optional_param = "{}&transaction_strictness={}".format(optional_param, param.get('transaction_strictness'))
        if param.get('timeout') is not None:
            optional_param = "{}&timeout={}".format(optional_param, param.get('timeout'))
        if param.get('suggest_domain') is not None:
            optional_param = "{}&suggest_domain={}".format(optional_param, param.get('suggest_domain'))
        if param.get('abuse_strictness') is not None:
            optional_param = "{}&abuse_strictness={}".format(optional_param, param.get('abuse_strictness'))
        if optional_param != '':
            req_url = "{}?{}".format(req_url, optional_param[1:])
        self.debug_print('req_url', req_url)
        return req_url

    def check_url(self, param):
        config = self.get_config()
        app_key = config.get('apikey', None)
        action_result = self.add_action_result(ActionResult(dict(param)))
        summary = action_result.update_summary({})

        ret_val, _ = self._validate_integer(action_result, param.get('strictness'), ipqualityscore_consts.STRICTNESS_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if param is None or param.get('url') is None:
            self.debug_print('Mandatory action parameters missing')
            action_result.set_status(phantom.APP_ERROR,
                                     ipqualityscore_consts.
                                     IPQUALITYSCORE_ERR_MSG_ACTION_PARAM)
            return action_result.get_status()
        else:
            if app_key:

                self.save_progress(ipqualityscore_consts.IPQUALITYSCORE_MSG_QUERY_URL,
                                   query_url=param.get('url'))
                try:
                    req_url = self.create_req_url('url', param, app_key)
                    query_res = requests.get(req_url)
                except Exception as e:
                    self.debug_print('check_url: ', e)
                    action_result.set_status(phantom.APP_ERROR,
                                             ipqualityscore_consts.
                                             IPQUALITYSCORE_SERVER_CONNECTION_ERROR, e)
                    return action_result.get_status()
            else:
                action_result.set_status(phantom.APP_ERROR,
                                         ipqualityscore_consts.
                                         IPQUALITYSCORE_ERR_MSG_ACTION_PARAM)
                return action_result.get_status()

            action_result.add_debug_data({'response_text': query_res.text
                                          if query_res else ''})
            self.debug_print('status_code', query_res.status_code)
            if query_res.status_code == 509:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    ipqualityscore_consts.
                    IPQUALITYSCORE_SERVER_ERROR_RATE_LIMIT)
            if query_res.status_code != 200:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    ipqualityscore_consts.
                    IPQUALITYSCORE_SERVER_RETURNED_ERROR_CODE.
                    format(code=query_res.status_code))
            try:
                result = query_res.json()
            except Exception as e:
                self.debug_print('Response from server is not a valid JSON', e)
                return action_result.set_status(
                    phantom.APP_ERROR,
                    'Response from server is not a valid JSON')

            if 'status_code' in result and result['status_code'] == 200:
                status = result['message']
                action_result.append_to_message(
                    ipqualityscore_consts.IPQUALITYSCORE_SERVICE_SUCC_MSG)
            else:
                action_result.set_status(
                    phantom.APP_ERROR,
                    ipqualityscore_consts.IPQUALITYSCORE_ERR_MSG_OBJECT_QUERIED)
                return action_result.get_status()
            try:
                status_summary = {}
                if result['success'] is True:
                    status_summary['Message'] = result["message"]
                    status_summary['Status_Code'] = result["status_code"]
                    status = {}
                    for key, val in result.items():
                        status[key] = val
                else:
                    status_summary['Message'] = result["message"]
                    status_summary['Status_Code'] = result["status_code"]
                summary.update(status_summary)
            except Exception as e:
                action_result.set_status(
                    phantom.APP_ERROR, 'Error populating summary', e)
                return action_result.get_status()

            action_result.add_data(status)
            action_result.set_status(phantom.APP_SUCCESS)
            return phantom.APP_SUCCESS

    def ip_reputation(self, param):
        config = self.get_config()
        app_key = config.get('apikey', None)
        action_result = self.add_action_result(ActionResult(dict(param)))
        summary = action_result.update_summary({})

        ret_val, _ = self._validate_integer(action_result, param.get('strictness'), ipqualityscore_consts.STRICTNESS_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, _ = self._validate_integer(action_result, param.get('transaction_strictness'), ipqualityscore_consts.TRANSACTION_STRICTNESS_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if param is None or param.get('ip') is None:
            self.debug_print('Mandatory action parameters missing')
            action_result.set_status(phantom.APP_ERROR,
                                     ipqualityscore_consts.
                                     IPQUALITYSCORE_ERR_MSG_ACTION_PARAM)
            return action_result.get_status()
        else:
            if app_key:
                self.save_progress(ipqualityscore_consts.IPQUALITYSCORE_MSG_QUERY_URL,
                                   query_ip=param.get('ip'))
                try:
                    req_url = self.create_req_url('ip', param, app_key)
                    query_res = requests.get(req_url)
                except Exception as e:
                    self.debug_print('ip_reputation: ', e)
                    action_result.set_status(phantom.APP_ERROR,
                                             ipqualityscore_consts.
                                             IPQUALITYSCORE_SERVER_CONNECTION_ERROR, e)
                    return action_result.get_status()
            else:
                action_result.set_status(phantom.APP_ERROR,
                                         ipqualityscore_consts.
                                         IPQUALITYSCORE_ERR_MSG_ACTION_PARAM)
                return action_result.get_status()

            action_result.add_debug_data({'response_text': query_res.text
                                          if query_res else ''})
            self.debug_print('status_code', query_res.status_code)
            if query_res.status_code == 509:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    ipqualityscore_consts.
                    IPQUALITYSCORE_SERVER_ERROR_RATE_LIMIT)
            if query_res.status_code != 200:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    ipqualityscore_consts.
                    IPQUALITYSCORE_SERVER_RETURNED_ERROR_CODE.
                    format(code=query_res.status_code))
            try:
                result = query_res.json()
            except Exception as e:
                self.debug_print('Response from server is not a valid JSON', e)
                return action_result.set_status(
                    phantom.APP_ERROR,
                    'Response from server is not a valid JSON')

            if 'success' in result and result['success'] is True:
                status = result['message']
                action_result.append_to_message(
                    ipqualityscore_consts.IPQUALITYSCORE_SERVICE_SUCC_MSG)
            else:
                action_result.set_status(
                    phantom.APP_ERROR,
                    ipqualityscore_consts.IPQUALITYSCORE_ERR_MSG_OBJECT_QUERIED)
                return action_result.get_status()
            try:
                status_summary = {}
                if result['success'] is True:
                    status_summary['Message'] = result["message"]
                    status_summary['Status_Code'] = 200
                    status = {}
                    for key, val in result.items():
                        status[key] = val
                else:
                    status_summary['Message'] = result["message"]
                    status_summary['Status_Code'] = 500
                summary.update(status_summary)
            except Exception as e:
                action_result.set_status(
                    phantom.APP_ERROR, 'Error populating summary', e)
                return action_result.get_status()
            action_result.add_data(status)
            action_result.set_status(phantom.APP_SUCCESS)
            return phantom.APP_SUCCESS

    def email_validation(self, param):
        config = self.get_config()
        app_key = config.get('apikey', None)
        action_result = self.add_action_result(ActionResult(dict(param)))
        summary = action_result.update_summary({})

        ret_val, _ = self._validate_integer(action_result, param.get('timeout'), ipqualityscore_consts.TIMEOUT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, _ = self._validate_integer(action_result, param.get('strictness'), ipqualityscore_consts.STRICTNESS_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, _ = self._validate_integer(action_result, param.get('abuse_strictness'), ipqualityscore_consts.ABUSE_STRICTNESS_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if param is None or param.get('email') is None:
            self.debug_print('Mandatory action parameters missing')
            action_result.set_status(phantom.APP_ERROR,
                                     ipqualityscore_consts.
                                     IPQUALITYSCORE_ERR_MSG_ACTION_PARAM)
            return action_result.get_status()
        else:
            if app_key:
                self.save_progress(ipqualityscore_consts.IPQUALITYSCORE_MSG_QUERY_URL,
                                   query_ip=param.get('email'))
                try:
                    req_url = self.create_req_url('email', param, app_key)
                    query_res = requests.get(req_url)
                except Exception as e:
                    self.debug_print('ip_reputation: ', e)
                    action_result.set_status(phantom.APP_ERROR,
                                             ipqualityscore_consts.
                                             IPQUALITYSCORE_SERVER_CONNECTION_ERROR, e)
                    return action_result.get_status()
            else:
                action_result.set_status(phantom.APP_ERROR,
                                         ipqualityscore_consts.
                                         IPQUALITYSCORE_ERR_MSG_ACTION_PARAM)
                return action_result.get_status()

            action_result.add_debug_data({'response_text': query_res.text
                                          if query_res else ''})
            self.debug_print('status_code', query_res.status_code)
            if query_res.status_code == 509:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    ipqualityscore_consts.
                    IPQUALITYSCORE_SERVER_ERROR_RATE_LIMIT)
            if query_res.status_code != 200:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    ipqualityscore_consts.
                    IPQUALITYSCORE_SERVER_RETURNED_ERROR_CODE.
                    format(code=query_res.status_code))
            try:
                result = query_res.json()
            except Exception as e:
                self.debug_print('Response from server is not a valid JSON', e)
                return action_result.set_status(
                    phantom.APP_ERROR,
                    'Response from server is not a valid JSON')

            if 'success' in result and result['success'] is True:
                status = result['message']
                action_result.append_to_message(
                    ipqualityscore_consts.IPQUALITYSCORE_SERVICE_SUCC_MSG)
            else:
                action_result.set_status(
                    phantom.APP_ERROR,
                    ipqualityscore_consts.IPQUALITYSCORE_ERR_MSG_OBJECT_QUERIED)
                return action_result.get_status()
            try:
                status_summary = {}
                if result['success'] is True:
                    status_summary['Message'] = result["message"]
                    status_summary['Status_Code'] = 200
                    status = result.copy()
                else:
                    status_summary['Message'] = result["message"]
                    status_summary['Status_Code'] = 500
                summary.update(status_summary)
            except Exception as e:
                action_result.set_status(
                    phantom.APP_ERROR, 'Error populating summary', e)
                return action_result.get_status()
            action_result.add_data(status)
            action_result.set_status(phantom.APP_SUCCESS)
            return phantom.APP_SUCCESS


if __name__ == '__main__':
    import sys
    import pudb
    pudb.set_trace()
    if len(sys.argv) < 2:
        print('No test json specified as input')
        exit(0)
    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = IpqualityscoreConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))
    exit(0)
