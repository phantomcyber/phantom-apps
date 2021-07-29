# File: awscloudtrail_connector.py
# Copyright (c) 2019-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

import json
import requests
import phantom.app as phantom
import botocore.response as br
import botocore.paginate as bp

from boto3 import client, Session
from awscloudtrail_consts import *
from botocore.config import Config
from datetime import datetime
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
import six
import ast


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class AwsCloudtrailConnector(BaseConnector):

    def __init__(self):

        super(AwsCloudtrailConnector, self).__init__()
        self._state = None
        self._access_key = None
        self._secret_key = None
        self._session_token = None
        self._region = None
        self._proxy = None

    def _handle_get_ec2_role(self):

        session = Session(region_name=self._region)
        credentials = session.get_credentials()
        return credentials

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

                self.save_progress("Using temporary assume role ceredentials for action")
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Failed to get temporary credentials:{0}".format(e))

        try:
            if self._access_key and self._secret_key:
                self.debug_print("Creating boto3 client with API keys")
                self._client = client(
                    'cloudtrail',
                    region_name=self._region,
                    aws_access_key_id=self._access_key,
                    aws_secret_access_key=self._secret_key,
                    aws_session_token=self._session_token,
                    config=boto_config)
            else:
                self.debug_print("Creating boto3 client without API keys")
                self._client = client(
                    'cloudtrail',
                    region_name=self._region,
                    config=boto_config)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Could not create boto3 client: {0}".format(e))

        return phantom.APP_SUCCESS

    def _extract_cloudtrail_event_object(self, ct_string):
        try:
            return json.loads(ct_string)
        except (ValueError, KeyError):
            return None

    def _make_boto_call(self, action_result, method, **kwargs):
        try:
            boto_func = getattr(self._client, method)
            can_paginate = self._client.can_paginate(boto_func.__name__)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {}".format(method)))

        set_name = AWSCLOUDTRAIL_DICT_MAP.get(method)
        updated_list = []

        try:
            resp_json = boto_func(**kwargs)
            if can_paginate:
                for e in resp_json.get(set_name):
                    new_obj = self._extract_cloudtrail_event_object(e['CloudTrailEvent'])
                    e['ExtractedCloudTrailEvent'] = new_obj
                    del e['CloudTrailEvent']
                    updated_list.append(e)
            else:
                resp_json = boto_func(**kwargs)
                for i in resp_json.get(set_name):
                    updated_list.append(i)
        except Exception as e:
            exception_message = e.args[0].strip()
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "boto3 call to CloudTrail failed.", exception_message),
                None)

        if can_paginate:
            next_token = None
            if resp_json and resp_json.get('NextToken'):
                next_token = resp_json.get('NextToken')

            res_dict = {
                "response_list": self._sanitize_data(updated_list),
                "next_token": next_token
            }
            return phantom.APP_SUCCESS, res_dict
        else:
            return phantom.APP_SUCCESS, self._sanitize_data(updated_list)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))),
                None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _paginator(self, method_name, limit, action_result, **kwargs):
        """
        This action is used to create an iterator that will paginate through responses from called methods.

        :param method_name: Name of method whose response is to be paginated
        :param action_result: Object of ActionResult class
        :param **kwargs: Dictionary of Input parameters
        """
        list_items = list()
        next_token = None

        while True:
            if next_token:
                kwargs['NextToken'] = next_token

            ret_val, response = self._make_boto_call(action_result, method_name, **kwargs)

            if phantom.is_fail(ret_val):
                return None

            if response is not None:
                if response.get('next_token'):
                    next_token = response.get("next_token")
                if response.get('response_list'):
                    list_items.extend(response.get('response_list'))

            if limit and len(list_items) >= limit:
                return list_items[:limit]

            if not next_token:
                break

        return list_items

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Querying AWS to validate credentials")

        if not self._create_client(action_result, param):
            return action_result.get_status()

        ret_val, resp = self._make_boto_call(action_result, "describe_trails", includeShadowTrails=False)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_describe_trails(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        include_shadow_trails = param.get('include_shadow_trails', False)

        # workaround for default-value weirdness with boolean types
        if include_shadow_trails == "true":
            include_shadow_trails = True

        if not self._create_client(action_result, param):
            return action_result.get_status()

        ret_val, resp_json = self._make_boto_call(action_result, "describe_trails", includeShadowTrails=include_shadow_trails)
        if phantom.is_fail(ret_val):
            self.save_progress("Connection to CloudTrails failed")
            return action_result.get_status()

        for trail in resp_json:
            action_result.add_data(trail)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['message'] = "Received {} trails".format(action_result.get_data_size())

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_run_query(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        attribute_key = param.get('attribute_key', '')
        attribute_value = param.get('attribute_value', '')
        start_date = param.get('start_date', '')
        end_date = param.get('end_date', '')
        limit = param.get('max_results', 50)

        if (limit and not str(limit).isdigit()) or limit == 0:
            return action_result.set_status(phantom.APP_ERROR, AWSCLOUDTRAIL_INVALID_LIMIT)

        # fail if we're not able to create a client
        if not self._create_client(action_result, param):
            return action_result.get_status()

        kwargs = {}           # define the kwargs to send to _make_boto_call
        if attribute_key != '' and attribute_value != '':
            kwargs['LookupAttributes'] = [{
                "AttributeKey": attribute_key,
                "AttributeValue": attribute_value
            }]

        # it is possible the user did not respect the format. Let try to do what we do and
        # inform them of the mistake if necessary.
        try:
            if start_date != '':
                kwargs['StartTime'] = datetime.strptime(start_date, "%Y-%m-%d")
            if end_date != '':
                kwargs['EndTime'] = datetime.strptime(end_date, "%Y-%m-%d")
        except ValueError:
            return RetVal(action_result.set_status(
                phantom.APP_ERROR,
                "Invalid date format. Remember to left-pad in the format of YYYY-MM-DD"), None)

        lookup_events = self._paginator("lookup_events", limit, action_result, **kwargs)

        if lookup_events is None:
            self.save_progress("Connection to CloudTrails failed")
            return action_result.get_status()

        for event in lookup_events:
            action_result.add_data(event)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary["total_lookup_events"] = action_result.get_data_size()
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)
        elif action_id == 'describe_trails':
            ret_val = self._handle_describe_trails(param)
        elif action_id == 'run_query':
            ret_val = self._handle_run_query(param)

        return ret_val

    def _sanitize_data(self, cur_obj):

        try:
            json.dumps(cur_obj)
            return cur_obj
        except:
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

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        # Load required configs
        self._region = AWS_CLOUDTRAIL_REGIONS.get(config['Region'])

        # handle proxies
        self._proxy = {}
        env_vars = config.get('_reserved_environment_variables', {})
        if 'HTTP_PROXY' in env_vars:
            self._proxy['http'] = env_vars['HTTP_PROXY']['value']
        if 'HTTPS_PROXY' in env_vars:
            self._proxy['https'] = env_vars['HTTPS_PROXY']['value']

        if config.get('use_role'):
            credentials = self._handle_get_ec2_role()
            if not credentials:
                return self.set_status(phantom.APP_ERROR, "Failed to get EC2 role credentials")
            self._access_key = credentials.access_key
            self._secret_key = credentials.secret_key
            self._session_token = credentials.token

            return phantom.APP_SUCCESS

        self._access_key = config.get('Access Key')
        self._secret_key = config.get('Secret Key')

        if not (self._access_key and self._secret_key):
            return self.set_status(phantom.APP_ERROR, AWSCLOUDTRAIL_BAD_ASSET_CONFIG_MSG)

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
            login_url = AwsCloudtrailConnector._get_phantom_base_url() + '/login'

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

        connector = AwsCloudtrailConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
