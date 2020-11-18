# File: awsguardduty_connector.py
# Copyright (c) 2019-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from awsguardduty_consts import *

import requests
import json
import time
from datetime import datetime, timedelta
from boto3 import client


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class AwsGuarddutyConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(AwsGuarddutyConnector, self).__init__()

        self._state = None
        self._region = None
        self._access_key = None
        self._secret_key = None
        self._base_url = None

    def _create_client(self, action_result):

        try:

            if self._access_key and self._secret_key:

                self.debug_print("Creating boto3 client with API keys")

                self._client = client(
                        'guardduty',
                        region_name=self._region,
                        aws_access_key_id=self._access_key,
                        aws_secret_access_key=self._secret_key)

            else:

                self.debug_print("Creating boto3 client without API keys")

                self._client = client(
                        'guardduty',
                        region_name=self._region)

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Could not create boto3 client: {0}".format(e))

        return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, param):
        """ This function is used to handle the test connectivity action.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to endpoint")

        if phantom.is_fail(self._create_client(action_result)):
            return action_result.get_status()

        ret_val, response = self._make_boto_call(action_result, 'list_invitations', MaxResults=1)

        if phantom.is_fail(ret_val) or response is None:
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

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

        artifact = {}
        artifact['name'] = 'Finding Artifact'
        artifact['container_id'] = container_id
        artifact['source_data_identifier'] = finding['Id']
        artifact['cef'] = finding

        create_artifact_status, create_artifact_msg, _ = self.save_artifacts([artifact])

        if phantom.is_fail(create_artifact_status):
            return phantom.APP_ERROR, create_artifact_msg

        return phantom.APP_SUCCESS, 'Artifacts created successfully'

    def _handle_on_poll(self, param):
        """ This function is used to handle on_poll.

       :param param: Dictionary of input parameters
       :return: status success/failure
       """

        self.debug_print("In action handler for: {0}".format(self.get_action_identifier()))
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result)):
            return action_result.get_status()

        config = self.get_config()
        days = config.get('poll_now_days', AWSGUARDDUTY_POLL_NOW_DAYS)
        filter_name = config.get('filter_name')

        # Validation of the poll_now_days
        if (days and not str(days).isdigit()) or days == 0:
            return action_result.set_status(phantom.APP_ERROR, AWSGUARDDUTY_INVALID_LIMIT.format(param_name='poll_now_days in asset configuration'))

        container_count = int(param.get(phantom.APP_JSON_CONTAINER_COUNT))

        end_time = datetime.now()

        # Fetch the start_time of polling for the first run
        initial_time = int(time.mktime((end_time - timedelta(int(days))).timetuple()) * 1000)

        if self._state.get('first_run', True) or self.is_poll_now() or ((filter_name or self._state.get('filter_name')) and filter_name != self._state.get('filter_name')):
            criteria_dict = { 'updatedAt': { 'Gt': initial_time } }
            if not self.is_poll_now() and self._state.get('first_run', True):
                self._state['first_run'] = False

            # Store the poll_now_days in state file to determine if the value of this parameter gets changed at an interim state
            if filter_name:
                self._state['filter_name'] = filter_name
            elif not filter_name and self._state.get('filter_name'):
                self._state.pop('filter_name')
        else:
            start_time = self._state.get('last_updated_time', initial_time)
            # Adding 1000 milliseconds for next scheduled run as the Gt filter operator fetches
            # based on Gteq at an accuracy of 1000 milliseconds due to some bug in AWS GuardDuty API
            criteria_dict = { 'updatedAt': { 'Gt': start_time + 1000 } }

        if not self._state.get('detector_id'):
            # Getting the detectors ID
            list_detectors = self._paginator('list_detectors', None, action_result)

            if not list_detectors:
                self.save_progress('No detectors found for AWS GuardDuty')
                return action_result.get_status()

            detector_id = list_detectors[0]

            self._state['detector_id'] = detector_id
        else:
            detector_id = self._state.get('detector_id')

        # Fetching the filter details
        finding_criteria = dict()
        if filter_name:
            ret_val, response = self._make_boto_call(action_result, 'get_filter', DetectorId=detector_id, FilterName=filter_name)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            finding_criteria = response.get('FindingCriteria', {})

        # Removing the existing filter criteria of updatedAt and explicitly using the start_time calculated above for the OnPoll logic
        try:
            finding_criteria['Criterion'].pop('updatedAt')
        except KeyError:
            pass
        # Creating the sorting criteria according to the polling method(poll now / scheduling)
        sort_criteria = { 'AttributeName': 'updatedAt', 'OrderBy': 'ASC' }
        if self.is_poll_now():
            sort_criteria = { 'AttributeName': 'updatedAt', 'OrderBy': 'DESC' }

        kwargs = {'DetectorId': detector_id, 'SortCriteria': sort_criteria}

        # Updates the Criterion by adding criteria_dict
        if finding_criteria:
            finding_criteria['Criterion'].update(criteria_dict)
        else:
            finding_criteria['Criterion'] = criteria_dict

        kwargs['FindingCriteria'] = finding_criteria

        list_findings = self._paginator('list_findings', None, action_result, **kwargs)

        if list_findings is None:
            self.save_progress('No findings found')
            return action_result.get_status()

        self.save_progress('Ingesting data')

        all_findings = list()

        # Fetches the details of finding in a bunch of 50 findings
        while list_findings:
            ret_val, res = self._make_boto_call(
                                    action_result, 'get_findings', DetectorId=detector_id, FindingIds=list_findings[:min(50, len(list_findings))], SortCriteria=sort_criteria)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            try:
                del res['ResponseMetadata']
            except:
                pass

            findings_data = res.get('Findings')

            if not findings_data:
                self.save_progress('No findings found')
                return action_result.get_status()

            for finding in findings_data:
                if finding.get('Severity'):
                    finding['Severity'] = AWSGUARDDUTY_SEVERITY_REVERSE_MAP.get(finding.get('Severity'))

            all_findings.extend(findings_data)

            del list_findings[:min(50, len(list_findings))]

        if not all_findings:
            self.save_progress('No new findings found to poll')
            return action_result.set_status(phantom.APP_SUCCESS)

        # Updates the last_update_time in the state file
        if not self.is_poll_now():
            last_finding = all_findings[(min(len(all_findings), container_count)) - 1]
            last_updated_at_datetime = datetime.strptime(str(last_finding.get('UpdatedAt')), AWSGUARDDUTY_DATETIME_FORMAT)
            self._state['last_updated_time'] = int(time.mktime(last_updated_at_datetime.timetuple())) * 1000

        for finding in all_findings[:container_count]:
            container_id = self._create_container(finding)

            if not container_id:
                continue

            artifacts_creation_status, artifacts_creation_msg = self._create_artifacts(finding=finding,
                                                                                       container_id=container_id)

            if phantom.is_fail(artifacts_creation_status):
                self.debug_print('Error while creating artifacts for container with ID {container_id}. {error_msg}'.
                                 format(container_id=container_id, error_msg=artifacts_creation_msg))

        self.save_progress('Total findings available on the UI of AWS GuardDuty: {}'.format(len(all_findings)))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _make_boto_call(self, action_result, method, **kwargs):

            try:
                boto_func = getattr(self._client, method)
            except AttributeError:
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), None)

            try:
                resp_json = boto_func(**kwargs)
            except Exception as e:
                return RetVal(action_result.set_status(phantom.APP_ERROR, 'boto3 call to Guardduty failed', e), None)

            return phantom.APP_SUCCESS, resp_json

    def _handle_update_finding(self, param):
        """
        Updates the finding by adding or changing the feedback and comment of the finding

        :param detector_id: The ID of the detector
        :param finding_id: The ID of the finding
        :param feedback: Feedback value of the finding
        :param comment: Additional feedback about the finding
        return: Details of updated finding
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result)):
            return action_result.get_status()

        detector_id = param['detector_id']
        finding_ids = param['finding_id']
        feedback = param['feedback']
        comments = param.get('comment')

        if comments:
            ret_val, response = self._make_boto_call(action_result,
                                                    'update_findings_feedback',
                                                    DetectorId=detector_id,
                                                    FindingIds=[finding_ids],
                                                    Feedback=feedback,
                                                    Comments=comments)
        else:
            ret_val, response = self._make_boto_call(action_result, 'update_findings_feedback', DetectorId=detector_id, FindingIds=[finding_ids], Feedback=feedback)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            del response['ResponseMetadata']
        except:
            pass

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['total_updated_findings'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _validate_findings_id(self, findings_ids, record_state, action_result, detector_id):

        # Validation of the correctness of the findings_id
        ret_val, res = self._make_boto_call(action_result, 'get_findings', DetectorId=detector_id, FindingIds=findings_ids)

        if phantom.is_fail(ret_val):
            return False

        if not res.get('Findings'):
            action_result.set_status(phantom.APP_ERROR, 'Please provide a valid Finding ID')
            return False
        else:
            finding = res.get('Findings')[0]
            finding_details = finding.get('Service')
            if finding_details:
                is_archived = finding_details.get('Archived')

            if (is_archived and record_state == 'ARCHIVED') or (not is_archived and record_state == 'UNARCHIVED'):
                action_result.set_status(phantom.APP_SUCCESS, 'The provided finding is already {}'.format(record_state))
                return False

        return True

    def _handle_archive_finding(self, param):
        """
        Archives Amazon GuardDuty findings specified by the detector ID and list of finding IDs

        :param detector_id: The ID of the detector
        :param finding_id: The ID of the finding
        return: Details of archived finding
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result)):
            return action_result.get_status()

        detector_id = param['detector_id']
        finding_id = param['finding_id']

        valid_findings_id = self._validate_findings_id([finding_id], 'ARCHIVED', action_result, detector_id)

        if not valid_findings_id:
            return action_result.get_status()

        ret_val, response = self._make_boto_call(action_result, 'archive_findings', DetectorId=detector_id, FindingIds=[finding_id])

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            del response['ResponseMetadata']
        except:
            pass

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['total_findings'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully archived the findings')

    def _handle_unarchive_finding(self, param):
        """
        Unarchives Amazon GuardDuty findings specified by the detector ID and list of finding IDs

        :param detector_id: The ID of the detector
        :param finding_id: The ID of the finding
        return: Details of unarchived finding
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result)):
            return action_result.get_status()

        detector_id = param['detector_id']
        finding_id = param['finding_id']

        valid_findings_id = self._validate_findings_id([finding_id], 'UNARCHIVED', action_result, detector_id)

        if not valid_findings_id:
            return action_result.get_status()

        ret_val, response = self._make_boto_call(action_result, 'unarchive_findings', DetectorId=detector_id, FindingIds=[finding_id])

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            del response['ResponseMetadata']
        except:
            pass

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['total_findings'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully unarchived the findings')

    def _paginator(self, method_name, limit, action_result, **kwargs):
        """
        Handles the pagination
        """

        list_items = list()
        next_token = None
        dic_map = {
            'list_filters': ['FilterNames'],
            'list_ip_sets': ['IpSetIds'],
            'list_threat_intel_sets': ['ThreatIntelSetIds'],
            'list_detectors': ['DetectorIds'],
            'list_findings': ['FindingIds']
        }

        set_name = dic_map.get(method_name)[0]

        while True:
            if next_token:
                ret_val, response = self._make_boto_call(action_result, method_name, NextToken=next_token, MaxResults=AWSGUARDDUTY_MAX_PER_PAGE_LIMIT, **kwargs)
            else:
                ret_val, response = self._make_boto_call(action_result, method_name, MaxResults=AWSGUARDDUTY_MAX_PER_PAGE_LIMIT, **kwargs)

            if phantom.is_fail(ret_val):
                return None

            if response.get(set_name):
                list_items.extend(response.get(set_name))

            if limit and len(list_items) >= limit:
                return list_items[:limit]

            next_token = response.get('NextToken')
            if not next_token:
                break

        return list_items

    def _handle_list_filters(self, param):
        """
        Returns a paginated list of the currently saved filters
        :param detector_id: The ID of the detector
        :param limit: Maximum results to be fetched
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result)):
            return action_result.get_status()

        detector_id = param['detector_id']
        limit = param.get('limit')

        if (limit and not str(limit).isdigit()) or limit == 0:
            return action_result.set_status(phantom.APP_ERROR, AWSGUARDDUTY_INVALID_LIMIT.format(param_name='limit'))

        kwargs = {'DetectorId': detector_id}

        list_filters = self._paginator('list_filters', limit, action_result, **kwargs)

        if list_filters is None:
           return action_result.get_status()

        for filter in list_filters:
            ret_val, res = self._make_boto_call(action_result, 'get_filter', DetectorId=detector_id, FilterName=filter)

            if phantom.is_fail(ret_val):
                return action_result.get_status()
            try:
                del res['ResponseMetadata']
            except:
                pass
            res['FilterName'] = filter
            action_result.add_data(res)

        summary = action_result.update_summary({})
        summary['total_filters'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_run_query(self, param):
        """
        Fetches all the findings controlled by the filters which provided as input

        :param detector_id: The ID of the detector
        :param instance_id: The ID of the EC2 instance
        :param severity: The severity of a finding
        :param public_ip: Public IP address of the EC2 instance
        :param private_ip: Private IP address of the EC2 instance
        :param limit: Maximum results to be fetched
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result)):
            return action_result.get_status()

        detector_id = param['detector_id']
        instance_id = param.get('instance_id')
        if param.get('severity'):
            severity = AWSGUARDDUTY_SEVERITY_MAP.get(param.get('severity'))
        else:
            severity = None
        public_ip = param.get('public_ip')
        private_ip = param.get('private_ip')
        limit = param.get('limit')

        if (limit and not str(limit).isdigit()) or limit == 0:
            return action_result.set_status(phantom.APP_ERROR, AWSGUARDDUTY_INVALID_LIMIT.format(param_name='limit'))

        criterion = {}
        finding_criteria = {
            "Criterion": criterion
        }

        if instance_id:
            criterion.update({
                'resource.instanceDetails.instanceId': {
                    'Eq': [
                        instance_id
                    ]
                }
            })

        if severity:
            criterion.update({
                'severity': {
                    'Eq': [
                        severity
                    ]
                }
            })

        if public_ip:
            criterion.update({
                'resource.instanceDetails.networkInterfaces.publicIp': {
                    'Eq': [
                        public_ip
                    ]
                }
            })

        if private_ip:
            criterion.update({
                'resource.instanceDetails.networkInterfaces.privateIpAddresses.privateIpAddress': {
                    'Eq': [
                        private_ip
                    ]
                }
            })

        kwargs = {'DetectorId': detector_id, 'FindingCriteria': finding_criteria}

        list_findings = self._paginator('list_findings', limit, action_result, **kwargs)

        if list_findings is None:
           return action_result.get_status()

        while list_findings:
            ret_val, res = self._make_boto_call(action_result, 'get_findings', DetectorId=detector_id, FindingIds=list_findings[:min(50, len(list_findings))])

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            try:
                del res['ResponseMetadata']
            except:
                pass

            findings_data = res.get('Findings')

            for finding in findings_data:
                if finding.get('Severity'):
                    finding['Severity'] = AWSGUARDDUTY_SEVERITY_REVERSE_MAP.get(finding.get('Severity'))
                action_result.add_data(finding)

            del list_findings[:min(50, len(list_findings))]

        summary = action_result.update_summary({})
        summary['total_findings'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_threats(self, param):
        """
        Lists the ThreatIntelSets of the GuardDuty service specified by the detector ID
        :param detector_id: The ID of the detector
        :param limit: Maximum results to be fetched
        """

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result)):
            return action_result.get_status()

        detector_id = param['detector_id']
        limit = param.get('limit')

        if (limit and not str(limit).isdigit()) or limit == 0:
            return action_result.set_status(phantom.APP_ERROR, AWSGUARDDUTY_INVALID_LIMIT.format(param_name='limit'))

        kwargs = {'DetectorId': detector_id}

        list_threats = self._paginator('list_threat_intel_sets', limit, action_result, **kwargs)

        if list_threats is None:
           return action_result.get_status()

        for threat in list_threats:
            ret_val, res = self._make_boto_call(action_result, 'get_threat_intel_set', DetectorId=detector_id, ThreatIntelSetId=threat)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            try:
                del res['ResponseMetadata']
            except:
                pass

            res['ThreatIntelSetId'] = threat
            action_result.add_data(res)

        summary = action_result.update_summary({})
        summary['total_threats'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_ip_sets(self, param):
        """
        Lists the IPSets of the GuardDuty service specified by the detector ID
        :param detector_id: The ID of the detector
        :param limit: Maximum results to be fetched
        """

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result)):
            return action_result.get_status()

        detector_id = param['detector_id']
        limit = param.get('limit')

        if (limit and not str(limit).isdigit()) or limit == 0:
            return action_result.set_status(phantom.APP_ERROR, AWSGUARDDUTY_INVALID_LIMIT.format(param_name='limit'))

        kwargs = {'DetectorId': detector_id}

        list_ip_sets = self._paginator('list_ip_sets', limit, action_result, **kwargs)

        if list_ip_sets is None:
           return action_result.get_status()

        for ip_set in list_ip_sets:
            ret_val, res = self._make_boto_call(action_result, 'get_ip_set', DetectorId=detector_id, IpSetId=ip_set)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            try:
                del res['ResponseMetadata']
            except:
                pass

            res['IpSetId'] = ip_set
            action_result.add_data(res)

        summary = action_result.update_summary({})
        summary['total_ip_sets'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_detectors(self, param):
        """
        Lists detectorIds of all the existing Amazon GuardDuty detector resources
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result)):
            return action_result.get_status()

        list_detectors = self._paginator('list_detectors', None, action_result)

        if list_detectors is None:
           return action_result.get_status()

        for detector in list_detectors:
            ret_val, res = self._make_boto_call(action_result, 'get_detector', DetectorId=detector)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            try:
                del res['ResponseMetadata']
            except:
                pass

            res['DetectorId'] = detector
            action_result.add_data(res)

        summary = action_result.update_summary({})
        summary['total_detectors'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        self.debug_print("action_id", self.get_action_identifier())

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'on_poll': self._handle_on_poll,
            'update_finding': self._handle_update_finding,
            'archive_finding': self._handle_archive_finding,
            'list_filters': self._handle_list_filters,
            'list_threats': self._handle_list_threats,
            'list_ip_sets': self._handle_list_ip_sets,
            'list_detectors': self._handle_list_detectors,
            'unarchive_finding': self._handle_unarchive_finding,
            'run_query': self._handle_run_query
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping.keys():
            action_function = action_mapping[action]
            action_execution_status = action_function(param)

        return action_execution_status

    def initialize(self):

        self._state = self.load_state()

        config = self.get_config()

        self._region = config['region']

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
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platform. Error: {}".format(str(e)))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = AwsGuarddutyConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
