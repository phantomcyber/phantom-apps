# File: awswaf_connector.py
# Copyright (c) 2019-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from awswaf_consts import *
from boto3 import client
from botocore.config import Config
from datetime import datetime
import botocore.response as br
import botocore.paginate as bp

import requests
import json
import ipaddress
import re


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class AwsWafConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(AwsWafConnector, self).__init__()

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._state = None
        self._region = None
        self._access_key = None
        self._secret_key = None
        self._proxy = None

    def _sanitize_data(self, cur_obj):

        try:
            json.dumps(cur_obj)
            return cur_obj
        except:
            pass

        if isinstance(cur_obj, dict):
            new_dict = {}
            for k, v in cur_obj.iteritems():
                if isinstance(v, br.StreamingBody):
                    content = v.read()
                    new_dict[k] = json.loads(content)
                else:
                    new_dict[k] = self._sanitize_data(v)
            return new_dict

        if isinstance(cur_obj, list):
            new_list = []
            for v in cur_obj:
                new_list.append(self._sanitize_data(v))
            return new_list

        if isinstance(cur_obj, datetime):
            return cur_obj.strftime("%Y-%m-%d %H:%M:%S")

        if isinstance(cur_obj, bp.PageIterator):
            new_dict = dict()
            try:
                for page in cur_obj:
                    new_dict.update(page)
                return new_dict
            except Exception as e:
                return { 'error': e }

        return cur_obj

    def _make_boto_call(self, action_result, method, paginate=False, empty_payload=False, **kwargs):

        try:
            boto_func = getattr(self._client, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), None)
        try:
            resp_json = boto_func(**kwargs)
        except Exception as e:
            exception_message = e.args[0].encode('utf-8').strip()
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'boto3 call to WAF failed', exception_message), None)

        return phantom.APP_SUCCESS, self._sanitize_data(resp_json)

    def _create_client(self, action_result):

        boto_config = None
        if self._proxy:
            boto_config = Config(proxies=self._proxy)

        try:
            if self._access_key and self._secret_key:
                self.debug_print("Creating boto3 client with API keys")
                self._client = client(
                    'waf',
                    region_name=self._region,
                    aws_access_key_id=self._access_key,
                    aws_secret_access_key=self._secret_key,
                    config=boto_config)
            else:
                self.debug_print("Creating boto3 client without API keys")
                self._client = client(
                    'waf',
                    region_name=self._region,
                    config=boto_config)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Could not create boto3 client: {0}".format(e))

        return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Querying AWS to check credentials")

        if not self._create_client(action_result):
            return action_result.get_status()

        # make rest call
        ret_val, resp_json = self._make_boto_call(action_result, 'list_rule_groups')

        if phantom.is_fail(ret_val) or resp_json is None:
            self.save_progress(AWSWAF_TEST_CONNECTIVITY_FAILED)
            return action_result.get_status()

        # Return success
        self.save_progress(AWSWAF_TEST_CONNECTIVITY_PASSED)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_ip(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ip_set_id = param.get('ip_set_id')
        ip_set_name = param.get('ip_set_name')
        ip_address = param.get('ip_address')

        if not ip_set_id and not ip_set_name:
            return action_result.set_status(phantom.APP_ERROR, AWSWAF_INSUFFICIENT_PARAM)

        ip_set = self.paginator(AWSWAF_DEFAULT_LIMIT, action_result)

        ip_set_id = self._verify_ip_set(action_result, ip_set, ip_set_id, ip_set_name)

        if not ip_set_id:
            if not param.get('ip_set_id') and param.get('ip_set_name'):
                # create a new IP set
                ret_val, resp_json = self._make_boto_call(action_result, 'get_change_token')

                if phantom.is_fail(ret_val):
                    return action_result.set_status(phantom.APP_ERROR, AWSWAF_ERR_TOKEN)

                ret_val, resp_json = self._make_boto_call(action_result, 'create_ip_set', Name=ip_set_name, ChangeToken=resp_json.get('ChangeToken'))

                if phantom.is_fail(ret_val):
                    return action_result.set_status(phantom.APP_ERROR, AWSWAF_ERR_CREATE_IPSET)

                ip_set_id = resp_json.get('IPSet', {}).get('IPSetId')
                action_result.add_data({'IpSetId': ip_set_id})
            else:
                return action_result.set_status(phantom.APP_ERROR, AWSWAF_INVALID_INPUT)

        type = self._validate_ip(ip_address)

        if type is None:
            return action_result.set_status(phantom.APP_ERROR, AWSWAF_IMPROPER_FORMAT)

        if not type:
            return action_result.set_status(phantom.APP_ERROR, AWSWAF_INVALID_IP)

        ret_val = self._ip_update(action_result, type, ip_address, ip_set_id)

        summary = action_result.update_summary({})
        summary['ip_status'] = 'IP added successfully'

        if phantom.is_fail(ret_val):
            summary['ip_status'] = 'IP could not be added'

        return action_result.get_status()

    def _verify_ip_set(self, action_result, ip_set, id, name):

        param = ""
        key = ""
        ip_set_id = ""
        if id:
            param = id
            key = 'IPSetId'
        else:
            param = name
            key = 'Name'
        for ipset in ip_set:
            if ipset.get(key) == param:
                ip_set_id = ipset.get('IPSetId')
                break

        return ip_set_id

    def _validate_ip(self, ip_address):
        type = ""
        x = re.search(".*\\/[0-9]+$", ip_address)
        if not (x):
            return None

        ip_add = unicode(ip_address.split('/')[0])
        try:
            ipaddress.IPv4Address(ip_add)
            return 'IPV4'
        except Exception:
            pass
        try:
            ipaddress.IPv6Address(ip_add)
            return 'IPV6'
        except Exception:
            return type

    def _ip_update(self, action_result, type, ip_address, ip_set_id):

        dic_map = {
            'add_ip': 'INSERT',
            'delete_ip': 'DELETE'
        }
        action = dic_map.get(self.get_action_identifier())
        updates_dict = dict()
        updates_dict['Action'] = action
        updates_dict['IPSetDescriptor'] = {
            'Type': type,
            'Value': ip_address
        }

        updates = [updates_dict]
        ret_val, resp_json = self._make_boto_call(action_result, 'get_change_token')

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, AWSWAF_ERR_TOKEN)

        try:
            ret_val, resp_json = self._make_boto_call(action_result, 'update_ip_set', ChangeToken=resp_json.get('ChangeToken'), IPSetId=ip_set_id, Updates=updates)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, str(e))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_ip(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ip_set_id = param.get('ip_set_id')
        ip_set_name = param.get('ip_set_name')
        ip_address = param.get('ip_address')

        if not ip_set_id and not ip_set_name:
            return action_result.set_status(phantom.APP_ERROR, AWSWAF_INSUFFICIENT_PARAM)

        ip_set = self.paginator(AWSWAF_DEFAULT_LIMIT, action_result)

        ip_set_id = self._verify_ip_set(action_result, ip_set, ip_set_id, ip_set_name)

        if not ip_set_id:
            return action_result.set_status(phantom.APP_ERROR, AWSWAF_INVALID_INPUT)

        type = self._validate_ip(ip_address)

        if type is None:
            return action_result.set_status(phantom.APP_ERROR, AWSWAF_IMPROPER_FORMAT)

        if not type:
            return action_result.set_status(phantom.APP_ERROR, AWSWAF_INVALID_IP)

        ret_val = self._ip_update(action_result, type, ip_address, ip_set_id)

        summary = action_result.update_summary({})
        summary['ip_status'] = 'IP deleted successfully'

        if phantom.is_fail(ret_val):
            summary['ip_status'] = 'IP could not be deleted'

        return action_result.get_status()

    def _handle_list_acls(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        limit = param.get('limit')
        if limit == 0 or (limit and (not str(limit).isdigit() or limit <= 0)):
            return action_result.set_status(phantom.APP_ERROR, AWSWAF_INVALID_LIMIT)

        set_list = self.paginator(limit, action_result)

        if set_list is None:
            return action_result.set_status(phantom.APP_ERROR, "Error while connecting")

        for item in set_list:
            action_result.add_data(item)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['number_of_acls'] = len(set_list)

        return action_result.set_status(phantom.APP_SUCCESS)

    def paginator(self, limit, action_result):

        if not self._create_client(action_result):
            return action_result.get_status()

        dic_map = {
            'list_rules': ['list_rules', 'Rules'],
            'list_ip_sets': ['list_ip_sets', 'IPSets'],
            'list_acls': ['list_web_acls', 'WebACLs'],
            'add_ip': ['list_ip_sets', 'IPSets'],
            'delete_ip': ['list_ip_sets', 'IPSets']
        }
        method_name = dic_map.get(self.get_action_identifier())[0]
        set_name = dic_map.get(self.get_action_identifier())[1]

        resp_json = dict()
        set_list = list()

        while True:
            if not resp_json.get('NextMarker'):
                ret_val, resp_json = self._make_boto_call(action_result, method_name, Limit=AWSWAF_DEFAULT_LIMIT)
            else:
                ret_val, resp_json = self._make_boto_call(action_result, method_name, Limit=AWSWAF_DEFAULT_LIMIT, NextMarker=resp_json.get('NextMarker'))

            if phantom.is_fail(ret_val) or resp_json is None:
                self.save_progress("Error while getting the {}".format(set_name))
                return None

            if (limit and limit <= AWSWAF_DEFAULT_LIMIT):
                set_list.extend(resp_json.get(set_name)[:limit])
                break
            elif method_name == 'list_rules':
                set_list.extend(resp_json.get(set_name))
                if len(resp_json.get(set_name)) <= AWSWAF_DEFAULT_LIMIT:
                    method_name = 'list_rate_based_rules'
                    resp_json['NextMarker'] = ""
            else:
                set_list.extend(resp_json.get(set_name))
                if not resp_json.get('NextMarker'):
                    break
                if limit:
                    limit = limit - AWSWAF_DEFAULT_LIMIT

        return set_list

    def _handle_list_rules(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        set_list = self.paginator(None, action_result)

        if set_list is None:
            return action_result.set_status(phantom.APP_ERROR, "Error while connecting")

        for item in set_list:
            action_result.add_data(item)

        summary = action_result.update_summary({})
        summary['number_of_rules'] = len(set_list)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_ip_sets(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        limit = param.get('limit')
        if limit == 0 or (limit and (not str(limit).isdigit() or limit <= 0)):
            return action_result.set_status(phantom.APP_ERROR, AWSWAF_INVALID_LIMIT)

        set_list = self.paginator(limit, action_result)

        if set_list is None:
            return action_result.set_status(phantom.APP_ERROR, "Error while connecting")

        # Add the response into the data section
        for item in set_list:
            action_result.add_data(item)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['number_of_ip_sets'] = len(set_list)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        # Get the action that we are supposed to execute for this App Run
        self.debug_print("action_id", self.get_action_identifier())

        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'add_ip': self._handle_add_ip,
            'delete_ip': self._handle_delete_ip,
            'list_acls': self._handle_list_acls,
            'list_rules': self._handle_list_rules,
            'list_ip_sets': self._handle_list_ip_sets
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping.keys():
            action_function = action_mapping[action]
            action_execution_status = action_function(param)

        return action_execution_status

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._access_key = config.get(AWSWAF_ACCESS_KEY)
        self._secret_key = config.get(AWSWAF_SECRET_KEY)
        self._region = AWSWAF_REGION_DICT.get(config[AWSWAF_REGION])

        self._proxy = {}
        env_vars = config.get('_reserved_environment_variables', {})
        if 'HTTP_PROXY' in env_vars:
            self._proxy['http'] = env_vars['HTTP_PROXY']['value']
        if 'HTTPS_PROXY' in env_vars:
            self._proxy['https'] = env_vars['HTTPS_PROXY']['value']

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
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
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

        connector = AwsWafConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
