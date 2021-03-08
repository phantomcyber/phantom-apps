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
            optional_param = optional_param + \
                "&strictness=" + str(param.get('strictness'))
        if param.get('user_agent') is not None:
            optional_param = optional_param + \
                "&user_agent=" + str(param.get('user_agent'))
        if param.get('user_language') is not None:
            optional_param = optional_param + \
                "&user_language=" + str(param.get('user_language'))
        if param.get('fast') is not None:
            optional_param = optional_param + "&fast=" + str(param.get('fast'))
        if param.get('mobile') is not None:
            optional_param = optional_param + "&mobile=" + str(param.get('mobile'))
        if param.get('allow_public_access_points') is not None:
            optional_param = optional_param + "&allow_public_access_points=" + \
                str(param.get('allow_public_access_points'))
        if param.get('lighter_penalties') is not None:
            optional_param = optional_param + "&lighter_penalties=" + \
                str(param.get('lighter_penalties'))
        if param.get('transaction_strictness') is not None:
            optional_param = optional_param + "&transaction_strictness=" + \
                str(param.get('transaction_strictness'))
        if param.get('timeout') is not None:
            optional_param = optional_param + \
                "&timeout=" + str(param.get('timeout'))
        if param.get('suggest_domain') is not None:
            optional_param = optional_param + \
                "&suggest_domain=" + str(param.get('suggest_domain'))
        if param.get('abuse_strictness') is not None:
            optional_param = optional_param + \
                "&abuse_strictness=" + str(param.get('abuse_strictness'))
        if optional_param != '':
            req_url = req_url + '?' + optional_param[1:]
        self.debug_print('req_url', req_url)
        return req_url

    def check_url(self, param):
        config = self.get_config()
        app_key = config.get('apikey', None)
        action_result = self.add_action_result(ActionResult(dict(param)))
        summary = action_result.update_summary({})
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
                self.debug_print('Response from server not a valid JSON', e)
                return action_result.set_status(
                    phantom.APP_ERROR,
                    'Response from server not' + ' a valid JSON')

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
                self.debug_print('Response from server not a valid JSON', e)
                return action_result.set_status(
                    phantom.APP_ERROR,
                    'Response from server not' + ' a valid JSON')

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
                self.debug_print('Response from server not a valid JSON', e)
                return action_result.set_status(
                    phantom.APP_ERROR,
                    'Response from server not' + ' a valid JSON')

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
