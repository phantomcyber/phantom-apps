# File: awslambda_connector.py
# Copyright (c) 2019-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from awslambda_consts import *
from boto3 import client
from datetime import datetime
from botocore.config import Config
import botocore.response as br
import botocore.paginate as bp
import requests
import json
import base64
import six


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class AwsLambdaConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(AwsLambdaConnector, self).__init__()

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
                return { 'error': e }

        return cur_obj

    def _make_boto_call(self, action_result, method, paginate=False, empty_payload=False, **kwargs):

        if paginate is False:
            try:
                boto_func = getattr(self._client, method)
            except AttributeError:
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), None)
            try:
                resp_json = boto_func(**kwargs)
                if empty_payload:
                    resp_json['Payload'] = {'body': "", 'statusCode': resp_json['StatusCode']}
            except Exception as e:
                exception_message = e.args[0].strip()
                return RetVal(action_result.set_status(phantom.APP_ERROR, 'boto3 call to Lambda failed', exception_message), None)
        else:
            try:
                paginator = self._client.get_paginator(method)
                resp_json = paginator.paginate(**kwargs)
            except Exception as e:
                return RetVal(action_result.set_status(phantom.APP_ERROR, 'boto3 call to Lambda failed', e), None)

        return phantom.APP_SUCCESS, self._sanitize_data(resp_json)

    def _create_client(self, action_result):

        boto_config = None
        if self._proxy:
            boto_config = Config(proxies=self._proxy)

        try:
            if self._access_key and self._secret_key:
                self.debug_print("Creating boto3 client with API keys")
                self._client = client(
                    'lambda',
                    region_name=self._region,
                    aws_access_key_id=self._access_key,
                    aws_secret_access_key=self._secret_key,
                    config=boto_config)
            else:
                self.debug_print("Creating boto3 client without API keys")
                self._client = client(
                    'lambda',
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
        ret_val, resp_json = self._make_boto_call(action_result, 'list_functions', MaxItems=1)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_invoke_lambda(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_client(action_result):
            return action_result.get_status()

        function_name = param['function_name']
        invocation_type = param.get('invocation_type')
        log_type = param.get('log_type')
        client_context = param.get('client_context')
        payload = param.get('payload')
        qualifier = param.get('qualifier')
        empty_payload = False

        args = {
            'FunctionName': function_name
        }
        if invocation_type:
            args['InvocationType'] = invocation_type
        if log_type:
            args['LogType'] = log_type
        if client_context:
            try:
                args['ClientContext'] = base64.b64encode(str(client_context)).decode('utf-8')
            except TypeError:  # py3
                args['ClientContext'] = base64.b64encode(client_context.encode('UTF-8')).decode('utf-8')
        if payload:
            args['Payload'] = payload
        if qualifier:
            args['Qualifier'] = qualifier

        if invocation_type == 'Event' or invocation_type == 'DryRun':
            empty_payload = True

        # make rest call
        ret_val, response = self._make_boto_call(action_result, 'invoke', False, empty_payload, **args)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        if response.get('FunctionError'):
            summary['status'] = 'Lambda invoked and returned FunctionError'
            return action_result.set_status(phantom.APP_ERROR, "Lambda invoked and returned FunctionError")
        else:
            summary['status'] = 'Successfully invoked lambda'

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_functions(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_client(action_result):
            return action_result.get_status()

        function_version = param.get('function_version')
        next_token = param.get('next_token')
        max_items = param.get('max_items')

        args = {}
        if function_version:
            args['FunctionVersion'] = function_version
        if next_token:
            args['Marker'] = next_token
        if max_items is not None:
            args['MaxItems'] = int(max_items)

        # make rest call
        ret_val, response = self._make_boto_call(action_result, 'list_functions', **args)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if response.get('error', None) is not None:
            return action_result.set_status(phantom.APP_ERROR, "{}".format(response.get('error')))

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_functions'] = len(response.get('Functions', {}))
        if response.get('NextMarker'):
            summary['next_token'] = response.get('NextMarker', 'Unavailable')

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_permission(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_client(action_result):
            return action_result.get_status()

        function_name = param['function_name']
        statement_id = param['statement_id']
        action = param['action']
        principal = param['principal']
        source_arn = param.get('source_arn')
        source_account = param.get('source_account')
        event_source_token = param.get('event_source_token')
        qualifier = param.get('qualifier')
        revision_id = param.get('revision_id')

        args = {
            'FunctionName': function_name,
            'StatementId': statement_id,
            'Action': action,
            'Principal': principal
        }
        if source_arn:
            args['SourceArn'] = source_arn
        if source_account:
            args['SourceAccount'] = source_account
        if event_source_token:
            args['EventSourceToken'] = event_source_token
        if qualifier:
            args['Qualifier'] = qualifier
        if revision_id:
            args['RevisionId'] = revision_id

        # make rest call
        ret_val, response = self._make_boto_call(action_result, 'add_permission', **args)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['status'] = "Successfully added permission"

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'invoke_lambda':
            ret_val = self._handle_invoke_lambda(param)

        elif action_id == 'list_functions':
            ret_val = self._handle_list_functions(param)

        elif action_id == 'add_permission':
            ret_val = self._handle_add_permission(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        if LAMBDA_JSON_ACCESS_KEY in config:
            self._access_key = config.get(LAMBDA_JSON_ACCESS_KEY)
        if LAMBDA_JSON_SECRET_KEY in config:
            self._secret_key = config.get(LAMBDA_JSON_SECRET_KEY)

        self._region = LAMBDA_REGION_DICT.get(config[LAMBDA_JSON_REGION])

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

        connector = AwsLambdaConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
