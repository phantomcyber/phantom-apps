# File: awssecurityhub_connector.py
# Copyright (c) 2016-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
import requests
import json
import ipaddress
from datetime import datetime, timedelta
from boto3 import client
from botocore.config import Config
from awssecurityhub_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class AwsSecurityHubConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(AwsSecurityHubConnector, self).__init__()

        self._state = None
        self._region = None
        self._access_key = None
        self._secret_key = None
        self._proxy = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def initialize(self):

        self._state = self.load_state()

        config = self.get_config()

        self._region = AWSSECURITYHUB_REGION_DICT.get(config['region'])
        if not self._region:
            return self.set_status(phantom.APP_ERROR, "Specified region is not valid")

        if 'access_key' in config:
            self._access_key = config['access_key']
        if 'secret_key' in config:
            self._secret_key = config['secret_key']

        self._proxy = {}
        env_vars = config.get('_reserved_environment_variables', {})
        if 'HTTP_PROXY' in env_vars:
            self._proxy['http'] = env_vars['HTTP_PROXY']['value']
        if 'HTTPS_PROXY' in env_vars:
            self._proxy['https'] = env_vars['HTTPS_PROXY']['value']

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _create_client(self, action_result, service='securityhub'):

        boto_config = None
        if self._proxy:
            boto_config = Config(proxies=self._proxy)

        try:
            if self._access_key and self._secret_key:

                self.debug_print("Creating boto3 client with API keys")
                self._client = client(
                        service,
                        region_name=self._region,
                        aws_access_key_id=self._access_key,
                        aws_secret_access_key=self._secret_key,
                        config=boto_config)
            else:

                self.debug_print("Creating boto3 client without API keys")
                self._client = client(
                        service,
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
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'boto3 call to Security Hub failed', e), None)

        return phantom.APP_SUCCESS, resp_json

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to endpoint")

        if phantom.is_fail(self._create_client(action_result)):
            return action_result.get_status()

        ret_val, response = self._make_boto_call(action_result, 'get_findings', MaxResults=1)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return ret_val

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _create_container(self, finding):
        """ This function is used to create the container in Phantom using finding data.

        :param finding: Data of single finding
        :return: container_id
        """

        container_dict = {}
        container_dict['name'] = finding['Title']
        container_dict['source_data_identifier'] = finding['Id']
        container_dict['description'] = finding['Description']

        container_creation_status, container_creation_msg, container_id = self.save_container(container=container_dict)

        if phantom.is_fail(container_creation_status):
            self.debug_print(container_creation_msg)
            self.save_progress('Error while creating container for finding {finding_id}. '
                               '{error_message}'.format(finding_id=finding['Id'],
                                                        error_message=container_creation_msg))
            return None

        return container_id

    def _create_artifacts(self, finding, container_id):
        """ This function is used to create artifacts in given container using finding data.

        :param finding: Data of single finding
        :param container_id: ID of container in which we have to create the artifacts
        :return: status(success/failure), message
        """

        artifacts = []

        for resource in finding.pop('Resources'):

            resource_artifact = {}
            resource_artifact['name'] = '{} Resource Artifact'.format(resource['Type'])
            resource_artifact['container_id'] = container_id
            resource_artifact['source_data_identifier'] = resource['Id']
            resource_artifact['cef'] = {}

            # Flatten the JSON, by moving the Details up one level
            if 'Details' in resource:
                resource_artifact['cef'].update(resource.pop('Details'))
            resource_artifact['cef'].update(resource)
            resource_artifact['cef_types'] = AWSSECURITYHUB_RESOURCE_CEF_TYPES

            # Extract the InstanceId from the ARN
            if 'instance/' in resource['Id']:
                resource_artifact['cef']['InstanceId'] = resource['Id'].split('instance/')[1]
                if resource['Type'] == 'AwsEc2Instance':
                    resource_artifact['cef_types']['InstanceId'] = ['aws ec2 instance id']

            artifacts.append(resource_artifact)

        finding_artifact = {}
        finding_artifact['name'] = 'Finding Artifact'
        finding_artifact['container_id'] = container_id
        finding_artifact['source_data_identifier'] = finding['Id']
        finding_artifact['cef'] = finding
        finding_artifact['cef_types'] = AWSSECURITYHUB_FINDING_CEF_TYPES
        artifacts.append(finding_artifact)

        create_artifact_status, create_artifact_msg, _ = self.save_artifacts(artifacts)

        if phantom.is_fail(create_artifact_status):
            return phantom.APP_ERROR, create_artifact_msg

        return phantom.APP_SUCCESS, 'Artifacts created successfully'

    def _poll_from_sqs(self, action_result, url, max_containers):

        if phantom.is_fail(self._create_client(action_result, service='sqs')):
            return None

        self.debug_print("THIS CONTAINER COUNT: {0}".format(max_containers))

        findings = []
        while len(findings) < max_containers:

            ret_val, resp_json = self._make_boto_call(action_result, 'receive_message', QueueUrl=url, MaxNumberOfMessages=AWSSECURITYHUB_SQS_MESSAGE_LIMIT)

            if phantom.is_fail(ret_val):
                return None

            if 'Messages' not in resp_json:
                return findings

            for message in resp_json['Messages']:
                message_dict = json.loads(message.get('Body', '{}'))
                if message_dict and message_dict.get('detail', {}).get('findings', []):
                    findings.extend(json.loads(message['Body'])['detail']['findings'])
                else:
                    return None

                ret_val, resp_json = self._make_boto_call(action_result, 'delete_message', QueueUrl=url, ReceiptHandle=message['ReceiptHandle'])

                if phantom.is_fail(ret_val):
                    self.debug_print("Could not delete message from SQS after receipt. This message may be received again in the future.")

            self.send_progress("Received {0} messages".format(min(len(findings), max_containers)))

        return findings[:max_containers]

    def _poll_from_security_hub(self, action_result, max_containers):

        config = self.get_config()

        if phantom.is_fail(self._create_client(action_result)):
            return None

        end_date = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if self.is_poll_now():
            days = int(config['poll_now_days'])
            filters = {
                        "UpdatedAt": [{
                            "DateRange": {
                                "Value": days,
                                "Unit": 'DAYS'
                            }
                        }]
                    }
        elif self._state.get('first_run', True):
            days = int(config['scheduled_poll_days'])
            filters = {
                        "UpdatedAt": [{
                            "DateRange": {
                                "Value": days,
                                "Unit": 'DAYS'
                            }
                        }]
                    }
        else:
            start_date = self._state.get('last_ingested_date')
            if not start_date:
                start_date = end_date - timedelta(days=int(config['scheduled_poll_days']))
            filters = {
                        "UpdatedAt": [{
                            "Start": start_date,
                            "End": end_date
                        }]
                    }

        findings = self._paginator('get_findings', filters, max_containers, action_result)

        if findings is None:
            return None

        if not self.is_poll_now():
            self._state['last_ingested_date'] = end_date
            if self._state.get('first_run', True):
                self._state['first_run'] = False

        return findings

    def _handle_on_poll(self, param):
        """ This function is used to handle on_poll.

       :param param: Dictionary of input parameters
       :return: status success/failure
       """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        config = self.get_config()
        container_count = int(param.get(phantom.APP_JSON_CONTAINER_COUNT))

        try:
            poll_now_days = int(config['poll_now_days'])
            if (poll_now_days and not str(poll_now_days).isdigit()) or poll_now_days == 0:
                return action_result.set_status(phantom.APP_ERROR, AWSSECURITYHUB_INVALID_INTEGER.format(parameter='poll_now_days'))
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, AWSSECURITYHUB_INVALID_DAYS.format(parameter='poll_now_days', error=str(e)))

        try:
            scheduled_poll_now_days = int(config['scheduled_poll_days'])
            if (scheduled_poll_now_days and not str(scheduled_poll_now_days).isdigit()) or scheduled_poll_now_days == 0:
                return action_result.set_status(phantom.APP_ERROR, AWSSECURITYHUB_INVALID_INTEGER.format(parameter='scheduled_poll_days'))
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, AWSSECURITYHUB_INVALID_DAYS.format(parameter='scheduled_poll_days', error=str(e)))

        if 'sqs_url' in config:
            findings = self._poll_from_sqs(action_result, config['sqs_url'], container_count)
        else:
            findings = self._poll_from_security_hub(action_result, container_count)

        if findings:
            self.save_progress('Ingesting data')
        elif findings is None:
            self.save_progress('Failed to get findings')
            return action_result.get_status()
        else:
            self.save_progress('No findings found')

        for finding in findings:

            container_id = self._create_container(finding)

            # If there is any error during creation of finding, skip that finding
            if not container_id:
                continue

            # Create artifacts for specific finding
            artifacts_creation_status, artifacts_creation_msg = self._create_artifacts(finding=finding, container_id=container_id)

            if phantom.is_fail(artifacts_creation_status):
                self.debug_print('Error while creating artifacts for container with ID {container_id}. {error_msg}'.
                                 format(container_id=container_id, error_msg=artifacts_creation_msg))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_findings(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result)):
            return action_result.get_status()

        limit = param.get('limit')

        if (limit and not str(limit).isdigit()) or limit == 0:
            return action_result.set_status(phantom.APP_ERROR, AWSSECURITYHUB_INVALID_INTEGER.format(parameter='limit'))

        resource_id = param.get('resource_id')
        resource_ec2_ipv4_addresses = param.get('resource_ec2_ipv4_addresses')
        network_source_ipv4 = param.get('network_source_ipv4')
        network_source_mac = param.get('network_source_mac')
        resource_region = param.get('resource_region')
        is_archived = param.get('is_archived')

        filters = dict()

        if resource_id:
            filters.update({
                "ResourceId": [{
                    "Value": resource_id,
                    "Comparison": AWSSECURITYHUB_EQUALS_CONSTS
                }]
            })

        if is_archived:
            filters.update({
                "RecordState": [{
                    "Value": 'ARCHIVED',
                    "Comparison": AWSSECURITYHUB_EQUALS_CONSTS
                }]
            })
        else:
            filters.update({
                "RecordState": [{
                    "Value": 'ACTIVE',
                    "Comparison": AWSSECURITYHUB_EQUALS_CONSTS
                }]
            })

        if resource_ec2_ipv4_addresses:
            ip_add_list = list()
            resource_ec2_ipv4_address_list = resource_ec2_ipv4_addresses.replace(" ", "").split(',')
            for ip_add in resource_ec2_ipv4_address_list:
                if ip_add:
                    try:
                        ipaddress.ip_address(str(ip_add))
                        ip_add_list.append({"Cidr": ip_add})
                    except:
                        self.debug_print('Resource ec2 IP validation failed for {}. Hence, skipping this IP address from being added to the filter.'.format(ip_add))

            if not ip_add_list:
                return action_result.set_status(phantom.APP_ERROR, 'Resource ec2 IP validation failed for all the provided IPs')

            filters.update({
                "ResourceAwsEc2InstanceIpV4Addresses": ip_add_list
            })

        if network_source_ipv4:
            ip_add_list = list()
            network_source_ipv4_list = network_source_ipv4.replace(" ", "").split(',')
            for ip_add in network_source_ipv4_list:
                if ip_add:
                    try:
                        ipaddress.ip_address(str(ip_add))
                        ip_add_list.append({"Cidr": ip_add})
                    except:
                        self.debug_print('Resource ec2 IP validation failed for {}. Hence, skipping this IP address from being added to the filter.'.format(ip_add))

            if not ip_add_list:
                return action_result.set_status(phantom.APP_ERROR, 'Network source IP validation failed validation failed for all the provided IPs')

            filters.update({
                "NetworkSourceIpV4": ip_add_list
            })

        if network_source_mac:
            filters.update({
                "NetworkSourceMac": [{
                    "Value": network_source_mac,
                    "Comparison": AWSSECURITYHUB_EQUALS_CONSTS
                }]
            })

        if resource_region:
            filters.update({
                "ResourceRegion": [{
                    "Value": resource_region,
                    "Comparison": AWSSECURITYHUB_EQUALS_CONSTS
                }]
            })

        list_findings = self._paginator('get_findings', filters, limit, action_result)

        if list_findings is None:
            return action_result.get_status()

        for finding in list_findings:
            resources = finding.get('Resources')
            if resources:
                for resource in resources:
                    resource_type = resource.get('Type')
                    if resource_type and 'AwsEc2Instance' == resource_type:
                        instance_list = resource.get('Id', '').split(':instance/i-')
                        if instance_list and len(instance_list) == 2:
                            resource['InstanceId'] = 'i-{0}'.format(instance_list[1])
            action_result.add_data(finding)

        summary = action_result.update_summary({})
        summary['total_findings'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _paginator(self, method_name, filters, limit, action_result):

        list_items = list()
        next_token = None

        while True:
            if next_token:
                ret_val, response = self._make_boto_call(action_result, method_name, Filters=filters, NextToken=next_token, MaxResults=AWSSECURITYHUB_MAX_PER_PAGE_LIMIT)
            else:
                ret_val, response = self._make_boto_call(action_result, method_name, Filters=filters, MaxResults=AWSSECURITYHUB_MAX_PER_PAGE_LIMIT)

            if phantom.is_fail(ret_val):
                return None

            if response.get('Findings'):
                list_items.extend(response.get('Findings'))

            if limit and len(list_items) >= int(limit):
                return list_items[:int(limit)]

            next_token = response.get('NextToken')
            if not next_token:
                break

        return list_items

    def _handle_get_related_findings(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result)):
            return action_result.get_status()

        findings_id = param['findings_id']

        valid_findings_id, _, finding = self._validate_findings_id(findings_id, None, action_result)

        if not (valid_findings_id and finding):
            return action_result.get_status()

        filters = {
            'Id': [{
                "Value": findings_id,
                "Comparison": AWSSECURITYHUB_EQUALS_CONSTS
            }]
        }
        ret_val, response = self._make_boto_call(action_result, 'get_findings', Filters=filters)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for finding in response.get("Findings", []):
            resources = finding.get('Resources')
            if resources:
                for resource in resources:
                    resource_type = resource.get('Type')
                    if resource_type and 'AwsEc2Instance' == resource_type:
                        instance_list = resource.get('Id', '').split(':instance/i-')
                        if instance_list and len(instance_list) == 2:
                            resource['InstanceId'] = 'i-{0}'.format(instance_list[1])
            action_result.add_data(finding)

        summary = action_result.update_summary({})
        summary['total_findings'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _validate_findings_id(self, findings_id, record_state, action_result):

        filters = {
                "Id": [{
                    "Comparison": AWSSECURITYHUB_EQUALS_CONSTS,
                    "Value": findings_id
                }]
            }

        # Validation of the correctness of the findings_id
        list_findings = self._paginator('get_findings', filters, None, action_result)

        if list_findings is None:
            return (False, False, None)

        for finding in list_findings:
            if finding.get('Id') == findings_id:
                if record_state and finding.get('RecordState') == record_state:
                    action_result.set_status(phantom.APP_SUCCESS, 'Provided findings ID is already {}'.format(record_state))
                    return (True, False, finding)
                break
        else:
            action_result.set_status(phantom.APP_ERROR, 'Please provide a valid findings ID')
            return (False, False, None)

        return (True, True, finding)

    def _handle_archive_findings(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result)):
            return action_result.get_status()

        note = param.get('note')
        findings_id = param['findings_id']
        note_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        valid_findings_id, to_archive, finding = self._validate_findings_id(findings_id, 'ARCHIVED', action_result)

        if not (valid_findings_id and to_archive):
            return action_result.get_status()

        filters = {
            'Id': [{
                "Value": findings_id,
                "Comparison": AWSSECURITYHUB_EQUALS_CONSTS
            }]
        }

        summary = action_result.update_summary({})
        summary['archive_note'] = 'Added successfully'
        summary['archived_status'] = 'Successful'

        # Add the note based on already existing add_note action's logic
        if note:
            overwrite = param.get('overwrite', False) or 'Note' not in finding
            note = note + ('' if overwrite else ('\n\n' + finding['Note']['Text']))

            note1 = {
                    'Text': '(Splunk Phantom - {0} time is {1}) {2}'.format('Archived updated', note_time, note),
                    'UpdatedBy': 'automation-splunk'
                }

            # Add the note
            ret_val, response = self._make_boto_call(action_result, 'update_findings', Filters=filters, Note=note1, RecordState='ARCHIVED')
        else:
            ret_val, response = self._make_boto_call(action_result, 'update_findings', Filters=filters, RecordState='ARCHIVED')
            summary['archive_note'] = 'Note is not added as it is not provided in the input parameters of the action'

        if phantom.is_fail(ret_val):
            summary['archive_note'] = 'Error occurred while adding note'
            summary['archived_status'] = 'Failed'
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unarchive_findings(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result)):
            return action_result.get_status()

        note = param.get('note')
        findings_id = param['findings_id']
        note_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        valid_findings_id, to_unarchive, finding = self._validate_findings_id(findings_id, 'ACTIVE', action_result)

        if not (valid_findings_id and to_unarchive):
            return action_result.get_status()

        filters = {
            'Id': [{
                "Value": findings_id,
                "Comparison": AWSSECURITYHUB_EQUALS_CONSTS
            }]
        }

        summary = action_result.update_summary({})
        summary['unarchive_note'] = 'Added successfully'
        summary['unarchived_status'] = 'Successful'

        # Add the note based on already existing add_note action's logic
        if note:
            overwrite = param.get('overwrite', False) or 'Note' not in finding
            note = note + ('' if overwrite else ('\n\n' + finding['Note']['Text']))

            note1 = {
                    'Text': '(Splunk Phantom - {0} time is {1}) {2}'.format('Unarchived updated', note_time, note),
                    'UpdatedBy': 'automation-splunk'
                }

            # Add the note
            ret_val, response = self._make_boto_call(action_result, 'update_findings', Filters=filters, Note=note1, RecordState='ACTIVE')
        else:
            ret_val, response = self._make_boto_call(action_result, 'update_findings', Filters=filters, RecordState='ACTIVE')
            summary['unarchive_note'] = 'Note is not added as it is not provided in the input parameters of the action'

        if phantom.is_fail(ret_val):
            summary['unarchive_note'] = 'Error occurred while adding note'
            summary['unarchived_status'] = 'Failed'
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_note(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result)):
            return action_result.get_status()

        findings_id = param['findings_id']
        note_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        valid_findings_id, _, finding = self._validate_findings_id(findings_id, None, action_result)

        if not (valid_findings_id and finding):
            return action_result.get_status()

        overwrite = param.get('overwrite', False) or 'Note' not in finding

        note = param['note'] + ('' if overwrite else ('\n\n' + finding['Note']['Text']))

        filters = {
            'Id': [{
                "Value": findings_id,
                "Comparison": AWSSECURITYHUB_EQUALS_CONSTS
            }]
        }

        note1 = {
                'Text': '(Splunk Phantom - {0}) {1}'.format(note_time, note),
                'UpdatedBy': 'automation-splunk'
            }

        ret_val, response = self._make_boto_call(action_result, 'update_findings', Filters=filters, Note=note1)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['add_note'] = 'Success'
        return action_result.set_status(phantom.APP_SUCCESS, 'Note added successfully to the provided findings ID')

    def handle_action(self, param):

        self.debug_print("action_id", self.get_action_identifier())

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'on_poll': self._handle_on_poll,
            'get_findings': self._handle_get_findings,
            'get_related_findings': self._handle_get_related_findings,
            'archive_findings': self._handle_archive_findings,
            'unarchive_findings': self._handle_unarchive_findings,
            'add_note': self._handle_add_note
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in list(action_mapping.keys()):
            action_function = action_mapping[action]
            action_execution_status = action_function(param)

        return action_execution_status


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
            login_url = BaseConnector._get_phantom_base_url() + '/login'
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
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = AwsSecurityHubConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
