# File: athena_connector.py
#
# Copyright (c) 2017-2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
import athena_consts as consts
import time
import json
import re
from boto3 import client, Session
from botocore.config import Config
import ast


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class AthenaConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(AthenaConnector, self).__init__()

        self._state = None
        self._client = None
        self._region = None
        self._access_key = None
        self._secret_key = None
        self._session_token = None
        self._proxy = None

    def initialize(self):

        self._state = self.load_state()

        config = self.get_config()
        self._region = config['region']

        if consts.ATHENA_JSON_ACCESS_KEY in config:
            self._access_key = config.get(consts.ATHENA_JSON_ACCESS_KEY)
        if consts.ATHENA_JSON_SECRET_KEY in config:
            self._secret_key = config.get(consts.ATHENA_JSON_SECRET_KEY)

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

        self._access_key = config.get(consts.ATHENA_JSON_ACCESS_KEY)
        self._secret_key = config.get(consts.ATHENA_JSON_SECRET_KEY)

        if not (self._access_key and self._secret_key):
            return self.set_status(phantom.APP_ERROR, consts.ATHENA_BAD_ASSET_CONFIG_MSG)

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS

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

                self.save_progress("Using temporary assume role credentials for action")
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR,
                                                "Failed to get temporary credentials: {0}".format(e))
        try:

            if self._access_key and self._secret_key:

                self.debug_print("Creating boto3 client with API keys")

                self._client = client(
                        'athena',
                        region_name=self._region,
                        aws_access_key_id=self._access_key,
                        aws_secret_access_key=self._secret_key,
                        aws_session_token=self._session_token,
                        config=boto_config)

            else:

                self.debug_print("Creating boto3 client without API keys")

                self._client = client(
                        'athena',
                        region_name=self._region,
                        config=boto_config)

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Could not create boto3 client: {0}".format(e))

        return phantom.APP_SUCCESS

    def _make_boto_call(self, action_result, method, **kwargs):

        try:
            boto_func = getattr(self._client, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), None)

        try:
            resp_json = boto_func(**kwargs)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'boto3 call to Athena failed', e), None)

        return phantom.APP_SUCCESS, resp_json

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_client(action_result, param):
            return action_result.get_status()

        ret_val, resp_json = self._make_boto_call(action_result, 'list_named_queries')

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed")
            return ret_val

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_queries(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_client(action_result, param):
            return action_result.get_status()

        ret_val, resp_json = self._make_boto_call(action_result, 'list_named_queries')
        if (phantom.is_fail(ret_val)):
            return ret_val

        count = 0
        for query_id in resp_json.get('NamedQueryIds', []):

            ret_val, query_json = self._make_boto_call(action_result, 'get_named_query', NamedQueryId=query_id)
            if (phantom.is_fail(ret_val)):
                return ret_val

            count += 1
            action_result.add_data(query_json)

        action_result.set_summary({'num_queries': count})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_run_query(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        query = param['query'].strip()
        s3 = param['s3_location']
        encryption = param.get('encryption')
        database = param.get('database')
        kms_key = self.get_config().get('kms_key')

        if not s3.startswith('s3://'):
            return action_result.set_status(phantom.APP_ERROR, "The S3 location does not appear to be correctly formatted. It should start with 's3://'")

        location_json = {'OutputLocation': s3}

        if encryption:

            encrypt_config = {}
            encrypt_config['EncryptionOption'] = encryption
            location_json['EncryptionConfiguration'] = encrypt_config

            if encryption in ['SSE_KMS', 'CSE_KMS']:
                if not kms_key:
                    return action_result.set_status(phantom.APP_ERROR, "KMS encryption requires asset to have KMS key configured.")
                encrypt_config['KmsKey'] = kms_key

        if not self._create_client(action_result, param):
            return action_result.get_status()

        reg_exp = re.compile('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')

        if reg_exp.match(query.lower()):

            ret_val, query_json = self._make_boto_call(action_result, 'get_named_query', NamedQueryId=query)
            if (phantom.is_fail(ret_val)):
                return ret_val

            query_str = query_json.get('NamedQuery', {}).get('QueryString')

            if not query:
                return action_result.set_status('Could not find named query - {0}'.format(query))

            query = query_str

        if database:
            ret_val, response = self._make_boto_call(action_result, 'start_query_execution', QueryString=query,
                    ResultConfiguration=location_json, QueryExecutionContext={'Database': database})
        else:
            ret_val, response = self._make_boto_call(action_result, 'start_query_execution', QueryString=query, ResultConfiguration=location_json)

        if (phantom.is_fail(ret_val)):
            return ret_val

        execution_id = response.get('QueryExecutionId')

        if not execution_id:
            return action_result.set_status(phantom.APP_ERROR, "Could not get query execution ID after starting query.")

        for i in range(0, 60):

            ret_val, response = self._make_boto_call(action_result, 'get_query_execution', QueryExecutionId=execution_id)
            if (phantom.is_fail(ret_val)):
                return ret_val

            status = response.get('QueryExecution', {}).get('Status', {}).get('State')
            if not status:
                return action_result.set_status(phantom.APP_ERROR, "Could not get query execution status after starting query.")

            if status == 'FAILED':
                return action_result.set_status(phantom.APP_ERROR, "Query execution failed: {0}"
                        .format(response.get('QueryExecution', {}).get('Status', {}).get('StateChangeReason', 'Unknown error')))

            elif status == 'CANCELLED':
                return action_result.set_status(phantom.APP_ERROR, "Query execution cancelled")

            elif status in ['RUNNING', 'QUEUED']:
                time.sleep(1)
                continue

            elif status == 'SUCCEEDED':
                break

        ret_val, response = self._make_boto_call(action_result, 'get_query_results', QueryExecutionId=execution_id)
        if (phantom.is_fail(ret_val)):
            return ret_val

        rows = response.get('ResultSet', {}).get('Rows', [{}])

        for row in rows:
            action_result.add_data(row.get('Data'))

        action_result.set_summary({ 'num_rows': len(rows) - 1 if len(rows) != 0 else 0})

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)
        elif action_id == 'list_queries':
            ret_val = self._handle_list_queries(param)
        elif action_id == 'run_query':
            ret_val = self._handle_run_query(param)

        return ret_val


if __name__ == '__main__':

    import sys
    # import pudb
    # pudb.set_trace()

    if (len(sys.argv) < 2):
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = AthenaConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
