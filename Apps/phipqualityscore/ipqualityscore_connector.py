# File: ipqualityscore_connector.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Local imports
from ipqualityscore_consts import *

# Global imports
import simplejson as json
import requests
import urllib.parse


class IpqualityscoreConnector(BaseConnector):

    def __init__(self):
        super(IpqualityscoreConnector, self).__init__()

    def handle_action(self, param):
        result = None
        action_id = self.get_action_identifier()
        if action_id == ACTION_ID_URL_CHECKER:
            result = self.check_url(param)
        elif action_id == ACTION_ID_IP_REPUTATION:
            result = self.ip_reputation(param)
        elif action_id == ACTION_ID_EMAIL_VALIDATION:
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

    def _validate_integer(self, action_result, parameter, key):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MSG.format(key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MSG.format(key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, NON_NEGATIVE_INTEGER_MSG.format(key)), None

        return phantom.APP_SUCCESS, parameter

    def test_asset_connectivity(self, param):
        config = self.get_config()
        app_key = config['apikey']
        self.save_progress(IPQUALITYSCORE_MSG_CONNECTING)
        try:
            response = requests.get(
                IPQUALITYSCORE_API_TEST.format(apikey=app_key))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.debug_print('test_asset_connectivity: {}'.format(err))
            err_msg = '{}. {}. Error Occurred: {}'.format(IPQUALITYSCORE_ERR_CONNECTIVITY_TEST, IPQUALITYSCORE_MSG_CHECK_CONNECTIVITY, err)
            return self.set_status(phantom.APP_ERROR, err_msg)

        if response.status_code == 509:
            self.save_progress(IPQUALITYSCORE_SERVER_ERR_RATE_LIMIT)
            self.save_progress(IPQUALITYSCORE_ERR_CONNECTIVITY_TEST)
            return self.set_status(phantom.APP_ERROR)
        if response.status_code != 200:
            self.save_progress('{}. {}'.format(IPQUALITYSCORE_SERVER_RETURNED_ERR_CODE.
                        format(code=response.status_code), IPQUALITYSCORE_MSG_CHECK_CONNECTIVITY))
            self.save_progress(IPQUALITYSCORE_ERR_CONNECTIVITY_TEST)
            return self.set_status(phantom.APP_ERROR)

        try:
            result = response.json()
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.debug_print('Response from server is not a valid JSON {}'.format(err))
            self.save_progress('Response from server is not a valid JSON')
            self.save_progress(IPQUALITYSCORE_ERR_CONNECTIVITY_TEST)
            return self.set_status(phantom.APP_ERROR)

        if result.get('success'):
            self.save_progress(IPQUALITYSCORE_SUCC_CONNECTIVITY_TEST)
            return self.set_status(phantom.APP_SUCCESS)

        self.save_progress(IPQUALITYSCORE_ERR_CONNECTIVITY_TEST)
        return self.set_status(phantom.APP_ERROR)

    def create_req_url(self, urltype, param, app_key):
        if urltype == "url":
            req_url = IPQUALITYSCORE_API_URL_CHECKER.format(
                apikey=app_key, url=urllib.parse.quote_plus(param['url']))
        elif urltype == "ip":
            req_url = IPQUALITYSCORE_API_IP_REPUTATION.format(
                apikey=app_key, ip=param['ip'])
        elif urltype == "email":
            req_url = IPQUALITYSCORE_API_EMAIL_VALIDATION.format(
                apikey=app_key, email=param['email'])
        else:
            req_url = ''
        # optional parameters
        optional_params = {
            'strictness': param.get('strictness'),
            'user_agent': param.get('user_agent'),
            'user_language': param.get('user_language'),
            'fast': param.get('fast'),
            'mobile': param.get('mobile'),
            'allow_public_access_points': param.get('allow_public_access_points'),
            'lighter_penalties': param.get('lighter_penalties'),
            'transaction_strictness': param.get('transaction_strictness'),
            'timeout': param.get('timeout'),
            'suggest_domain': param.get('suggest_domain'),
            'abuse_strictness': param.get('abuse_strictness'),
        }
        query_string = '&'.join(f'{k}={v}' for k, v in optional_params.items() if v is not None)
        if query_string:
            req_url = "{}?{}".format(req_url, query_string)
        self.debug_print('req_url {}'.format(req_url))
        return req_url

    def check_url(self, param):
        config = self.get_config()
        app_key = config['apikey']
        action_result = self.add_action_result(ActionResult(dict(param)))
        summary = action_result.update_summary({})

        ret_val, _ = self._validate_integer(action_result, param.get('strictness'), STRICTNESS_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.save_progress(IPQUALITYSCORE_MSG_QUERY_URL,
                        query_url=param['url'])
        try:
            req_url = self.create_req_url('url', param, app_key)
            query_res = requests.get(req_url)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.debug_print('check_url: {}'.format(err))
            return action_result.set_status(phantom.APP_ERROR, '{}{}'.format(IPQUALITYSCORE_SERVER_CONNECTION_ERR, err))

        action_result.add_debug_data({'response_text': query_res.text
                                        if query_res else ''})
        self.debug_print('status_code {}'.format(query_res.status_code))
        if query_res.status_code == 509:
            return action_result.set_status(
                phantom.APP_ERROR,
                IPQUALITYSCORE_SERVER_ERR_RATE_LIMIT)
        if query_res.status_code != 200:
            return action_result.set_status(
                phantom.APP_ERROR,
                IPQUALITYSCORE_SERVER_RETURNED_ERR_CODE.
                format(code=query_res.status_code))
        try:
            result = query_res.json()
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.debug_print('Response from server is not a valid JSON {}'.format(err))
            return action_result.set_status(
                phantom.APP_ERROR,
                'Response from server is not a valid JSON')

        if 'status_code' in result and result['status_code'] == 200:
            status = result['message']
            action_result.append_to_message(
                IPQUALITYSCORE_SERVICE_SUCC_MSG)
        else:
            return action_result.set_status(
                phantom.APP_ERROR,
                IPQUALITYSCORE_ERR_MSG_OBJECT_QUERIED)

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
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, 'Error populating summary {}'.format(err))

        action_result.add_data(status)
        return action_result.set_status(phantom.APP_SUCCESS)

    def ip_reputation(self, param):
        config = self.get_config()
        app_key = config['apikey']
        action_result = self.add_action_result(ActionResult(dict(param)))
        summary = action_result.update_summary({})

        ret_val, _ = self._validate_integer(action_result, param.get('strictness'), STRICTNESS_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, _ = self._validate_integer(action_result, param.get('transaction_strictness'), TRANSACTION_STRICTNESS_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.save_progress(IPQUALITYSCORE_MSG_QUERY_URL,
                            query_ip=param['ip'])
        try:
            req_url = self.create_req_url('ip', param, app_key)
            query_res = requests.get(req_url)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.debug_print('ip_reputation: {}'.format(err))
            return action_result.set_status(phantom.APP_ERROR, '{}{}'.format(IPQUALITYSCORE_SERVER_CONNECTION_ERR, err))

        action_result.add_debug_data({'response_text': query_res.text
                                        if query_res else ''})
        self.debug_print('status_code {}'.format(query_res.status_code))
        if query_res.status_code == 509:
            return action_result.set_status(
                phantom.APP_ERROR, IPQUALITYSCORE_SERVER_ERR_RATE_LIMIT)
        if query_res.status_code != 200:
            return action_result.set_status(
                phantom.APP_ERROR, IPQUALITYSCORE_SERVER_RETURNED_ERR_CODE.
                format(code=query_res.status_code))
        try:
            result = query_res.json()
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.debug_print('Response from server is not a valid JSON {}'.format(err))
            return action_result.set_status(
                phantom.APP_ERROR,
                'Response from server is not a valid JSON')

        if result.get('success'):
            status = result['message']
            action_result.append_to_message(
                IPQUALITYSCORE_SERVICE_SUCC_MSG)
        else:
            return action_result.set_status(
                phantom.APP_ERROR,
                IPQUALITYSCORE_ERR_MSG_OBJECT_QUERIED)

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
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, 'Error populating summary {}'.format(err))

        action_result.add_data(status)
        return action_result.set_status(phantom.APP_SUCCESS)

    def email_validation(self, param):
        config = self.get_config()
        app_key = config['apikey']
        action_result = self.add_action_result(ActionResult(dict(param)))
        summary = action_result.update_summary({})

        ret_val, _ = self._validate_integer(action_result, param.get('timeout'), TIMEOUT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, _ = self._validate_integer(action_result, param.get('strictness'), STRICTNESS_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, _ = self._validate_integer(action_result, param.get('abuse_strictness'), ABUSE_STRICTNESS_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.save_progress(IPQUALITYSCORE_MSG_QUERY_URL,
                            query_ip=param['email'])
        try:
            req_url = self.create_req_url('email', param, app_key)
            query_res = requests.get(req_url)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.debug_print('ip_reputation: {}'.format(err))
            return action_result.set_status(phantom.APP_ERROR, '{}{}'.format(IPQUALITYSCORE_SERVER_CONNECTION_ERR, err))

        action_result.add_debug_data({'response_text': query_res.text
                                        if query_res else ''})
        self.debug_print('status_code {}'.format(query_res.status_code))
        if query_res.status_code == 509:
            return action_result.set_status(
                phantom.APP_ERROR,
                IPQUALITYSCORE_SERVER_ERR_RATE_LIMIT)
        if query_res.status_code != 200:
            return action_result.set_status(
                phantom.APP_ERROR,
                IPQUALITYSCORE_SERVER_RETURNED_ERR_CODE.
                format(code=query_res.status_code))
        try:
            result = query_res.json()
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.debug_print('Response from server is not a valid JSON {}'.format(err))
            return action_result.set_status(
                phantom.APP_ERROR,
                'Response from server is not a valid JSON')

        if result.get('success'):
            status = result['message']
            action_result.append_to_message(
                IPQUALITYSCORE_SERVICE_SUCC_MSG)
        else:
            return action_result.set_status(
                phantom.APP_ERROR,
                IPQUALITYSCORE_ERR_MSG_OBJECT_QUERIED)
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
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, 'Error populating summary {}'.format(err))

        action_result.add_data(status)
        return action_result.set_status(phantom.APP_SUCCESS)


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
