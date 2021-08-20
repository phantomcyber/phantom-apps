# File: awsguardduty_connector.py
# Copyright (c) 2019-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

import requests
import json
import time
from boto3 import client, Session
from datetime import datetime, timedelta
from botocore.config import Config
from awsguardduty_consts import *
from bs4 import UnicodeDammit
import sys
import ast


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
        self._session_token = None
        self._base_url = None
        self._proxy = None

    def _handle_py_ver_compat_for_input_str(self, input_str, always_encode=False):
        """
        This method returns the encoded|original string based on the Python version.
        :param input_str: Input string to be processed
        :param always_encode: Used if the string needs to be encoded for python 3
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """

        try:
            if input_str is not None and (self._python_version == 2 or always_encode):
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except:
            self.debug_print(AWSGUARDDUTY_PY_2TO3_ERR_MSG)

        return input_str

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_code = AWSGUARDDUTY_ERR_CODE_UNAVAILABLE
        error_msg = AWSGUARDDUTY_ERR_MSG_UNAVAILABLE

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = AWSGUARDDUTY_ERR_CODE_UNAVAILABLE
                    error_msg = e.args[0]
        except:
            pass

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = AWSGUARDDUTY_UNICODE_DAMMIT_TYPE_ERR_MSG
        except:
            error_msg = AWSGUARDDUTY_ERR_MSG_UNAVAILABLE

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        """ This method is to check if the provided input parameter value
        is a non-zero positive integer and returns the integer value of the parameter itself.

        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :param key: input parameter message key
        :allow_zero: whether zero should be considered as valid value or not
        :return: integer value of the parameter or None in case of failure
        """

        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, AWSGUARDDUTY_VALID_INT_MSG.format(param=key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, AWSGUARDDUTY_VALID_INT_MSG.format(param=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, AWSGUARDDUTY_NON_NEG_INT_MSG.format(param=key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, AWSGUARDDUTY_NON_NEG_NON_ZERO_INT_MSG.format(param=key)), None

        return phantom.APP_SUCCESS, parameter

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
                                                "Failed to get temporary credentials: {}".format(e))

        try:
            if self._access_key and self._secret_key:
                self.debug_print("Creating boto3 client with API keys")
                self._client = client(
                        'guardduty',
                        region_name=self._region,
                        aws_access_key_id=self._access_key,
                        aws_secret_access_key=self._secret_key,
                        aws_session_token=self._session_token,
                        config=boto_config)
            else:
                self.debug_print("Creating boto3 client without API keys")
                self._client = client(
                        'guardduty',
                        region_name=self._region,
                        config=boto_config)

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "{0}. {1}".format(AWSGUARDDUTY_CREATE_CLIENT_ERR_MSG, err_msg))

        return phantom.APP_SUCCESS

    def _sanitize_dates(self, cur_obj):

        try:
            json.dumps(cur_obj)
            return cur_obj
        except:
            pass

        if isinstance(cur_obj, dict):
            new_dict = {}
            for k, v in cur_obj.items():
                new_dict[k] = self._sanitize_dates(v)
            return new_dict

        if isinstance(cur_obj, list):
            new_list = []
            for v in cur_obj:
                new_list.append(self._sanitize_dates(v))
            return new_list

        if isinstance(cur_obj, datetime):
            return cur_obj.strftime("%Y-%m-%d %H:%M:%S")

        return cur_obj

    def _handle_test_connectivity(self, param):
        """ This function is used to handle the test connectivity action.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to endpoint")

        if phantom.is_fail(self._create_client(action_result, param)):
            return action_result.get_status()

        ret_val, _ = self._make_boto_call(action_result, 'list_invitations', MaxResults=1)

        if phantom.is_fail(ret_val):
            self.save_progress(AWSGUARDDUTY_TEST_CONN_FAILED_MSG)
            return action_result.get_status()

        self.save_progress(AWSGUARDDUTY_TEST_CONN_PASSED_MSG)
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
            self.save_progress('{}. {error_message}'.format(AWSGUARDDUTY_CREATE_CONTAINER_ERR_MSG.format(finding_id=finding['Id']), error_message=container_creation_msg))
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

        return phantom.APP_SUCCESS, AWSGUARDDUTY_CREATE_ARTIFACT_MSG

    def _handle_on_poll(self, param):  # noqa: C901
        """ This function is used to handle on_poll.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        self.debug_print("In action handler for: {0}".format(self.get_action_identifier()))
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result, param)):
            return action_result.get_status()

        filter_name = self._filter_name

        container_count = int(param.get(phantom.APP_JSON_CONTAINER_COUNT))

        end_time = datetime.now()

        # Fetch the start_time of polling for the first run
        initial_time = int(time.mktime((end_time - timedelta(self._days)).timetuple()) * 1000)

        if self._state.get('first_run', True) or self.is_poll_now() or ((filter_name or self._state.get('filter_name')) and filter_name != self._state.get('filter_name')):
            criteria_dict = { 'updatedAt': { 'Gt': initial_time } }
            if not self.is_poll_now() and self._state.get('first_run', True):
                self._state['first_run'] = False

            # Store the 'filter_name' in state file to determine if the value of this parameter gets changed at an interim state
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

        # Removing the existing filter criteria of updatedAt and explicitly using the start_time calculated above for the On Poll logic
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

                    # Parse S3 bucket details
                    try:
                        s3BucketDetails_list = finding['Resource']['S3BucketDetails']
                        if s3BucketDetails_list:
                            s3BucketDetails_dict = {}
                            for element in s3BucketDetails_list:
                                s3BucketDetails_dict[element['Arn']] = element
                            finding['Resource']['S3BucketDetails'] = s3BucketDetails_dict
                    except:
                        continue

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
                self.debug_print('{}. {error_msg}'.format(AWSGUARDDUTY_CREATE_ARTIFACT_ERR_MSG.format(container_id=container_id), error_msg=artifacts_creation_msg))

        self.save_progress('Total findings available on the UI of AWS GuardDuty: {}'.format(len(all_findings)))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _make_boto_call(self, action_result, method, **kwargs):

        try:
            boto_func = getattr(self._client, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, AWSGUARDDUTY_INVALID_METHOD_ERR_MSG.format(method=method)), None)

        try:
            resp_json = boto_func(**kwargs)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, '{0}. {1}'.format(AWSGUARDDUTY_BOTO3_CONN_FAILED_MSG, err_msg)), None)

        try:
            resp_json = self._sanitize_dates(resp_json)
        except:
            return RetVal(action_result.set_status(phantom.APP_ERROR, AWSGUARDDUTY_PROCESS_RESPONSE_ERR_MSG), None)

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

        if phantom.is_fail(self._create_client(action_result, param)):
            return action_result.get_status()

        detector_id = param['detector_id']
        finding_ids = param['finding_id']

        # Comma separated list handling for 'finding_id'
        finding_ids = [x.strip() for x in finding_ids.split(',')]
        finding_ids = list(filter(None, finding_ids))
        if not finding_ids:
            return action_result.set_status(phantom.APP_ERROR, AWSGUARDDUTY_INVALID_FINDING_ID_ERR_MSG)

        feedback = param['feedback']
        if feedback not in AWSGUARDDUTY_FEEDBACK_LIST:
            return action_result.set_status(phantom.APP_ERROR, AWSGUARDDUTY_INVALID_FEEDBACK_ERR_MSG)

        ret_val, valid_findings_ids = self._validate_findings_id(finding_ids, None, action_result, detector_id)
        if not ret_val:
            return action_result.get_status()
        self.debug_print("Valid finding IDs are: \n{}".format(valid_findings_ids))

        comments = param.get('comment')
        while valid_findings_ids:
            if comments:
                ret_val, response = self._make_boto_call(action_result,
                                                        'update_findings_feedback',
                                                        DetectorId=detector_id,
                                                        FindingIds=valid_findings_ids[:min(50, len(valid_findings_ids))],
                                                        Feedback=feedback,
                                                        Comments=comments)
            else:
                ret_val, response = self._make_boto_call(action_result,
                                                        'update_findings_feedback',
                                                        DetectorId=detector_id,
                                                        FindingIds=valid_findings_ids[:min(50, len(valid_findings_ids))],
                                                        Feedback=feedback)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            try:
                del response['ResponseMetadata']
            except:
                pass
            action_result.add_data(response)
            del valid_findings_ids[:min(50, len(valid_findings_ids))]

        return action_result.set_status(phantom.APP_SUCCESS, AWSGUARDDUTY_UPDATE_FINDING_SUCC_MSG)

    def _validate_findings_id(self, findings_ids, record_state, action_result, detector_id):

        # Validation of the correctness of the findings_ids
        valid_finding_ids = []

        # Check for valid ID found
        valid_id_found = False

        while findings_ids:
            ret_val, res = self._make_boto_call(action_result, 'get_findings', DetectorId=detector_id, FindingIds=findings_ids[:min(50, len(findings_ids))])

            if phantom.is_fail(ret_val):
                return False, valid_finding_ids

            if not res.get('Findings'):
                del findings_ids[:min(50, len(findings_ids))]
                continue

            if self.get_action_identifier() == "update_finding":
                for finding in res.get('Findings'):
                    if not valid_id_found:
                        valid_id_found = True
                    valid_finding_ids.append(finding['Id'])
            else:
                for finding in res.get('Findings'):
                    if not valid_id_found:
                        valid_id_found = True
                    finding_details = finding.get('Service')
                    if finding_details:
                        is_archived = finding_details.get('Archived')
                    else:
                        self.debug_print("No finding details for finding ID: {}".format(finding['Id']))
                        continue

                    if (is_archived and record_state == 'ARCHIVED') or (not is_archived and record_state == 'UNARCHIVED'):
                        self.debug_print("The finding ID {} is already in {}".format(finding['Id'], record_state))
                        continue
                    valid_finding_ids.append(finding['Id'])

            del findings_ids[:min(50, len(findings_ids))]

        if not valid_id_found:
            action_result.set_status(phantom.APP_ERROR, AWSGUARDDUTY_FINDING_ID_NOT_FOUND_ERR_MSG)
            return False, valid_finding_ids

        if not valid_finding_ids:
            action_result.set_status(phantom.APP_SUCCESS, AWSGUARDDUTY_FINDING_ID_IN_RECORD_STATE_ERR_MSG.format(record_state=record_state))
            return False, valid_finding_ids
        return True, valid_finding_ids

    def _handle_archive_finding(self, param):
        """
        Archives Amazon GuardDuty findings specified by the detector ID and list of finding IDs

        :param detector_id: The ID of the detector
        :param finding_id: The ID of the finding
        return: Details of archived finding
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result, param)):
            return action_result.get_status()

        detector_id = param['detector_id']
        finding_ids = param['finding_id']

        # Comma separated list handling for 'finding_id'
        finding_ids = [x.strip() for x in finding_ids.split(',')]
        finding_ids = list(filter(None, finding_ids))
        if not finding_ids:
            return action_result.set_status(phantom.APP_ERROR, AWSGUARDDUTY_INVALID_FINDING_ID_ERR_MSG)

        ret_val, valid_findings_ids = self._validate_findings_id(finding_ids, 'ARCHIVED', action_result, detector_id)
        self.debug_print("Valid finding IDs are: \n{}".format(valid_findings_ids))
        if not ret_val:
            return action_result.get_status()

        while valid_findings_ids:
            ret_val, response = self._make_boto_call(action_result, 'archive_findings', DetectorId=detector_id, FindingIds=valid_findings_ids[:min(50, len(valid_findings_ids))])
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            try:
                del response['ResponseMetadata']
            except:
                pass

            action_result.add_data(response)
            del valid_findings_ids[:min(50, len(valid_findings_ids))]

        return action_result.set_status(phantom.APP_SUCCESS, AWSGUARDDUTY_ARCHIVE_FINDING_SUCC_MSG)

    def _handle_unarchive_finding(self, param):
        """
        Unarchive Amazon GuardDuty findings specified by the detector ID and list of finding IDs

        :param detector_id: The ID of the detector
        :param finding_id: The ID of the finding
        return: Details of unarchived findings
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result, param)):
            return action_result.get_status()

        detector_id = param['detector_id']
        finding_ids = param['finding_id']

        # Comma separated list handling for 'finding_id'
        finding_ids = [x.strip() for x in finding_ids.split(',')]
        finding_ids = list(filter(None, finding_ids))
        if not finding_ids:
            return action_result.set_status(phantom.APP_ERROR, AWSGUARDDUTY_INVALID_FINDING_ID_ERR_MSG)

        ret_val, valid_findings_ids = self._validate_findings_id(finding_ids, 'UNARCHIVED', action_result, detector_id)
        if not ret_val:
            return action_result.get_status()
        self.debug_print("Valid finding IDs are: \n{}".format(valid_findings_ids))

        while valid_findings_ids:
            ret_val, response = self._make_boto_call(action_result, 'unarchive_findings', DetectorId=detector_id, FindingIds=valid_findings_ids[:min(50, len(valid_findings_ids))])
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            try:
                del response['ResponseMetadata']
            except:
                pass

            action_result.add_data(response)
            del valid_findings_ids[:min(50, len(valid_findings_ids))]

        return action_result.set_status(phantom.APP_SUCCESS, AWSGUARDDUTY_UNARCHIVE_FINDING_SUCC_MSG)

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

        if phantom.is_fail(self._create_client(action_result, param)):
            return action_result.get_status()

        detector_id = param['detector_id']
        limit = param.get('limit')

        # Integer validation for 'limit' action parameter
        ret_val, limit = self._validate_integer(action_result, limit, AWSGUARDDUTY_LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

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
        Fetches all the findings controlled by the filters which are provided as input

        :param detector_id: The ID of the detector
        :param instance_id: The ID of the EC2 instance
        :param severity: The severity of a finding
        :param public_ip: Public IP address of the EC2 instance
        :param private_ip: Private IP address of the EC2 instance
        :param limit: Maximum results to be fetched
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result, param)):
            return action_result.get_status()

        detector_id = param['detector_id']
        instance_id = param.get('instance_id')
        severity = param.get('severity')
        if severity:
            severity = AWSGUARDDUTY_SEVERITY_MAP.get(param.get('severity'))
            if not severity:
                return action_result.set_status(phantom.APP_ERROR, AWSGUARDDUTY_INVALID_SEVERITY_ERR_MSG)

        public_ip = param.get('public_ip')
        private_ip = param.get('private_ip')
        limit = param.get('limit')

        # Integer validation for 'limit' action parameter
        ret_val, limit = self._validate_integer(action_result, limit, AWSGUARDDUTY_LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

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

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result, param)):
            return action_result.get_status()

        detector_id = param['detector_id']
        limit = param.get('limit')

        # Integer validation for 'limit' action parameter
        ret_val, limit = self._validate_integer(action_result, limit, AWSGUARDDUTY_LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

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

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result, param)):
            return action_result.get_status()

        detector_id = param['detector_id']
        limit = param.get('limit')

        # Integer validation for 'limit' action parameter
        ret_val, limit = self._validate_integer(action_result, limit, AWSGUARDDUTY_LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

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

        if phantom.is_fail(self._create_client(action_result, param)):
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

    def _handle_get_ec2_role(self):

        session = Session(region_name=self._region)
        credentials = session.get_credentials()
        return credentials

    def initialize(self):

        self._state = self.load_state()

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, AWSGUARDDUTY_ERR_FETCHING_PYTHON_VERSION_MSG)

        config = self.get_config()

        self._days = config.get('poll_now_days', AWSGUARDDUTY_POLL_NOW_DAYS)

        # Integer validation for 'poll_now_days' configuration parameter
        ret_val, self._days = self._validate_integer(self, self._days, AWSGUARDDUTY_POLL_NOW_DAYS_KEY)
        if phantom.is_fail(ret_val):
            return self.get_status()

        self._filter_name = config.get('filter_name')
        self._region = AWSGUARDDUTY_REGION_DICT.get(config[AWSGUARDDUTY_JSON_REGION])

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

        self._access_key = config.get('access_key')
        self._secret_key = config.get('secret_key')

        if not (self._access_key and self._secret_key):
            return self.set_status(phantom.APP_ERROR, AWSGUARDDUTY_BAD_ASSET_CONFIG_ERR_MSG)

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
            login_url = BaseConnector._get_phantom_base_url() + '/login'
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
            print("Unable to get session id from the platform. Error: {}".format(str(e)))
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
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
