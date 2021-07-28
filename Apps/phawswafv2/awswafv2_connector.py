# File: awswafv2_connector.py
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

import ipaddress
import json
import re
from datetime import datetime

import botocore.paginate as bp
import botocore.response as br
import phantom.app as phantom
import requests
import six
import ast
from boto3 import client, Session
from botocore.config import Config
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from awswafv2_consts import *


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
        self._scope = None
        self._access_key = None
        self._secret_key = None
        self._session_token = None
        self._proxy = None

    def _sanitize_data(self, cur_obj):

        try:
            json.dumps(cur_obj)
            return cur_obj
        except Exception:
            pass

        if isinstance(cur_obj, dict):
            new_dict = {}
            for k, v in six.iteritems(cur_obj):
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
                return {'error': e}

        return cur_obj

    def _make_boto_call(self, action_result, method, paginate=False, empty_payload=False, **kwargs):

        try:
            boto_func = getattr(self._client, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), None)
        try:
            resp_json = boto_func(Scope=self._scope, **kwargs)
        except Exception as e:
            exception_message = e.args[0].strip()
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'boto3 call to WAF failed', exception_message),
                          None)

        return phantom.APP_SUCCESS, self._sanitize_data(resp_json)

    def _create_client(self, action_result, param=None):

        boto_config = None
        if self._proxy:
            boto_config = Config(proxies=self._proxy)

        # Try getting and using temporary assume role credentials from parameters
        temp_credentials = dict()
        if param and 'credentials' in param:
            try:
                temp_credentials = ast.literal_eval(param['credentials'])
                self._access_key = temp_credentials.get('AccessKeyId', '')
                self._secret_key = temp_credentials.get('SecretAccessKey', '')
                self._session_token = temp_credentials.get('SessionToken', '')

                self.save_progress("Using temporary assume role credentials for action")
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Failed to get temporary credentials:{0}".format(e))

        try:
            if self._access_key and self._secret_key:
                self.debug_print("Creating boto3 client with API keys")
                self._client = client(
                    AWSWAF_VERSION_V2,
                    region_name=self._region,
                    aws_access_key_id=self._access_key,
                    aws_secret_access_key=self._secret_key,
                    aws_session_token=self._session_token,
                    config=boto_config)
            else:
                self.debug_print("Creating boto3 client without API keys")
                self._client = client(
                    AWSWAF_VERSION_V2,
                    region_name=self._region,
                    config=boto_config)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Could not create boto3 client: {0}".format(e))

        return phantom.APP_SUCCESS

    def _verify_ip_set(self, action_result, ip_set, id, name):

        ip_set_id = ""
        ip_set_name = ""
        if id:
            param = id
            key = 'Id'
        else:
            param = name
            key = 'Name'
        for ipset in ip_set:
            if ipset.get(key) == param:
                ip_set_id = ipset.get('Id')
                ip_set_name = ipset.get('Name')
                break

        return ip_set_id, ip_set_name

    def _validate_ip(self, ip_address):
        x = re.search(".*\\/[0-9]+$", ip_address)
        if not x:
            return None

        ip_add = ip_address.split('/')[0]
        try:
            ipaddress.IPv4Address(ip_add)
            return 'IPV4'
        except Exception:
            pass
        try:
            ipaddress.IPv6Address(ip_add)
            return 'IPV6'
        except Exception:
            return None

    def _ip_update(self, action_result, ip_address_list, ip_set_id, ip_set_name):
        # get_ip_set call for retrieving lock_token and ip_address
        try:
            ret_val, resp_json = self._make_boto_call(action_result, 'get_ip_set', Name=ip_set_name, Id=ip_set_id)
            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR, AWSWAF_ERR_GET_IPSET)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, str(e))

        # getting existing ip addresses from ip set
        list_addresses = resp_json.get('IPSet', {}).get('Addresses', [])
        lock_token = resp_json.get('LockToken')

        # update ip address based on action
        if AWSWAF_ADD_IP == self.get_action_identifier():
            list_addresses.extend(ip_address_list)
        elif AWSWAF_DELETE_IP == self.get_action_identifier():
            try:
                for ip_address in ip_address_list:
                    list_addresses.remove(ip_address)
            except ValueError:
                return action_result.set_status(phantom.APP_ERROR, AWSWAF_ERR_IP_NOT_FOUND)

        # Update call using lock token and updated list of ip_address
        try:
            ret_val, resp_json = self._make_boto_call(action_result, 'update_ip_set', Name=ip_set_name,
                                                      Id=ip_set_id, Addresses=list_addresses,
                                                      LockToken=lock_token)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, str(e))

        action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS)

    def paginator(self, limit, action_result, param):

        if not self._create_client(action_result, param):
            return action_result.get_status()

        action_identifier_map = {
            'list_ip_sets': ['list_ip_sets', 'IPSets'],
            'list_acls': ['list_web_acls', 'WebACLs'],
            'add_ip': ['list_ip_sets', 'IPSets'],
            'delete_ip': ['list_ip_sets', 'IPSets']
        }

        action_identifier = self.get_action_identifier()
        if action_identifier not in action_identifier_map:
            return []

        method_name = action_identifier_map.get(action_identifier)[0]
        set_name = action_identifier_map.get(action_identifier)[1]

        resp_json = dict()
        set_list = list()

        while True:
            if not resp_json.get('NextMarker'):
                ret_val, resp_json = self._make_boto_call(action_result, method_name, Limit=AWSWAF_DEFAULT_LIMIT)
            else:
                ret_val, resp_json = self._make_boto_call(action_result, method_name, Limit=AWSWAF_DEFAULT_LIMIT,
                                                          NextMarker=resp_json.get('NextMarker'))

            if phantom.is_fail(ret_val) or resp_json is None:
                self.save_progress("Error while getting the {}".format(set_name))
                return None

            if limit and limit <= AWSWAF_DEFAULT_LIMIT:
                set_list.extend(resp_json.get(set_name)[:limit])
                break
            else:
                set_list.extend(resp_json.get(set_name))
                if not resp_json.get('NextMarker'):
                    break
                if limit:
                    limit -= AWSWAF_DEFAULT_LIMIT

        return set_list

    def validate_params(self, action_result, ip_set_id, ip_set_name, ip_address_list):

        ip_type = ''
        if not ip_set_id and not ip_set_name:
            return action_result.set_status(phantom.APP_ERROR, AWSWAF_INSUFFICIENT_PARAM)

        for ip_address in ip_address_list:
            ip_type = self._validate_ip(ip_address)

            if ip_type is None:
                return action_result.set_status(phantom.APP_ERROR, AWSWAF_INVALID_IP)

            if not ip_type:
                return action_result.set_status(phantom.APP_ERROR, AWSWAF_INVALID_IP)

        return ip_type

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress(AWSWAF_INFO_CHECK_CREDENTIALS)
        self.save_progress(AWSWAF_INFO_SCOPE)

        if not self._create_client(action_result, param):
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

        self.save_progress(AWSWAF_INFO_ACTION.format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ip_set_id = param.get('ip_set_id')
        ip_set_name = param.get('ip_set_name')
        ip_address = param.get('ip_address')
        ip_address_list = [x.strip() for x in ip_address.split(',') if x.strip()]
        ip_type = self.validate_params(action_result, ip_set_id, ip_set_name, ip_address_list)

        ip_set = self.paginator(AWSWAF_DEFAULT_LIMIT, action_result, param)
        ip_set_id, ip_set_name = self._verify_ip_set(action_result, ip_set, ip_set_id, ip_set_name)

        if not ip_set_id:
            ip_set_name = param.get('ip_set_name')
            # create a new IP set with given IP addresses
            ret_val, resp_json = self._make_boto_call(action_result, 'create_ip_set', Name=ip_set_name,
                                                      IPAddressVersion=ip_type, Addresses=ip_address_list)

            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR, AWSWAF_ERR_CREATE_IPSET)

            action_result.set_status(phantom.APP_SUCCESS)
            ip_set_id = resp_json.get('Summary', {}).get('Id')
            action_result.add_data({'Id': ip_set_id})
        else:
            ret_val = self._ip_update(action_result, ip_address_list, ip_set_id, ip_set_name)

        summary = action_result.update_summary({})

        if phantom.is_fail(ret_val):
            summary['ip_status'] = AWSWAF_ADD_IP_FAILED

        summary['ip_status'] = AWSWAF_ADD_IP_SUCCESS

        return action_result.get_status()

    def _handle_delete_ip(self, param):

        self.save_progress(AWSWAF_INFO_ACTION.format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ip_set_id = param.get('ip_set_id')
        ip_set_name = param.get('ip_set_name')
        ip_address = param.get('ip_address')

        ip_address_list = [x.strip() for x in ip_address.split(',') if x.strip()]
        _ = self.validate_params(action_result, ip_set_id, ip_set_name, ip_address_list)

        ip_set = self.paginator(AWSWAF_DEFAULT_LIMIT, action_result, param)

        ip_set_id, ip_set_name = self._verify_ip_set(action_result, ip_set, ip_set_id, ip_set_name)

        if not ip_set_id:
            return action_result.set_status(phantom.APP_ERROR, AWSWAF_INVALID_INPUT)

        ret_val = self._ip_update(action_result, ip_address_list, ip_set_id, ip_set_name)

        summary = action_result.update_summary({})

        if phantom.is_fail(ret_val):
            summary['ip_status'] = AWSWAF_DELETE_IP_FAILED

        summary['ip_status'] = AWSWAF_DELETE_IP_SUCCESS

        return action_result.get_status()

    def _handle_list_acls(self, param):

        self.save_progress(AWSWAF_INFO_ACTION.format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        limit = param.get('limit')
        if limit == 0 or (limit and (not str(limit).isdigit() or limit <= 0)):
            return action_result.set_status(phantom.APP_ERROR, AWSWAF_INVALID_LIMIT)

        set_list = self.paginator(limit, action_result, param)

        if set_list is None:
            return action_result.set_status(phantom.APP_ERROR, AWSWAF_ERR_LIST_WEBACLS)

        for item in set_list:
            action_result.add_data(item)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['number of acls'] = len(set_list)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_ip_sets(self, param):
        self.save_progress(AWSWAF_INFO_ACTION.format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        limit = param.get('limit')
        if limit == 0 or (limit and (not str(limit).isdigit() or limit <= 0)):
            return action_result.set_status(phantom.APP_ERROR, AWSWAF_INVALID_LIMIT)

        set_list = self.paginator(limit, action_result, param)

        if set_list is None:
            return action_result.set_status(phantom.APP_ERROR, AWSWAF_ERR_LIST_IPSET)

        # Add the response into the data section
        for item in set_list:
            action_result.add_data(item)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['number of ip sets'] = len(set_list)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        # Get the action that we are supposed to execute for this App Run
        self.debug_print("action_id", self.get_action_identifier())

        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'add_ip': self._handle_add_ip,
            'delete_ip': self._handle_delete_ip,
            'list_acls': self._handle_list_acls,
            'list_ip_sets': self._handle_list_ip_sets
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping.keys():
            action_function = action_mapping[action]
            action_execution_status = action_function(param)

        return action_execution_status

    def _handle_get_ec2_role(self):

        session = Session(region_name=self._region)
        credentials = session.get_credentials()
        return credentials

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        if config.get('use_role'):
            credentials = self._handle_get_ec2_role()
            if not credentials:
                return self.set_status(phantom.APP_ERROR, "Failed to get EC2 role credentials")
            self._access_key = credentials.access_key
            self._secret_key = credentials.secret_key
            self._session_token = credentials.token

            return phantom.APP_SUCCESS

        self._access_key = config.get(AWSWAF_ACCESS_KEY)
        self._secret_key = config.get(AWSWAF_SECRET_KEY)

        if not (self._access_key and self._secret_key):
            return self.set_status(phantom.APP_ERROR, AWSWAF_BAD_ASSET_CFG_ERR_MSG)

        self._region = AWSWAF_REGION_DICT.get(config[AWSWAF_REGION])
        self._scope = config.get(AWSWAF_SCOPE)

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

        connector = AwsWafConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
