# -----------------------------------------
# IronNet Phantom Connector
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import json
import re
from bs4 import UnicodeDammit
import swagger_client
import sys
from swagger_client.rest import ApiException
from ironnet_consts import *

severity_mapping = {
    "undecided": "SEVERITY_UNDECIDED",
    "benign": "SEVERITY_BENIGN",
    "suspicious": "SEVERITY_SUSPICIOUS",
    "malicious": "SEVERITY_MALICIOUS"
}
expectation_mapping = {
    "expected": "EXP_EXPECTED",
    "unexpected": "EXP_UNEXPECTED",
    "unknown": "EXP_UNKNOWN"
}

status_mapping = {
    "awaiting review": "STATUS_AWAITING_REVIEW",
    "under review": "STATUS_UNDER_REVIEW",
    "closed": "STATUS_CLOSED"
}

# Phantom ts format
phantom_ts = re.compile('^(\\d+-\\d+-\\d+) (\\d+:\\d+\\d+:\\d+\\.\\d+\\+\\d+)$')


def fix_timestamp(timestamp):
    # Attempts to reformat the given timestamp as RFC3339
    match = phantom_ts.match(timestamp)
    if(match):
        return "{0}T{1}:00".format(match.group(1), match.group(2))
    return timestamp


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class IronnetConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(IronnetConnector, self).__init__()

        self._state = None

        self._base_url = None
        self._username = None
        self._password = None
        self._verify_server_cert = None
        self._enable_alert_notifications = None
        self._alert_notification_actions = None
        self._alert_categories = None
        self._alert_subcategories = None
        self._alert_severity_lower = None
        self._alert_severity_upper = None
        self._alert_limit = None
        self._enable_dome_notifications = None
        self._dome_categories = None
        self._dome_limit = None
        self._enable_event_notifications = None
        self._alert_event_actions = None
        self._event_categories = None
        self._event_subcategories = None
        self._event_severity_lower = None
        self._event_severity_upper = None
        self._event_limit = None
        self._store_event_notifs_in_alert_containers = None
        self._api_instance = None

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.
        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """

        try:
            if input_str and self._python_version == 2:

                input_str = UnicodeDammit(
                    input_str).unicode_markup.encode('utf-8')
        except:
            self.debug_print(
                "Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def _validate_integer(self, action_result, parameter, key):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, INT_VALIDATION_ERR_MSG.format(key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, INT_VALIDATION_ERR_MSG.format(key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, "Please provide a valid non-negative integer value in the {}".format(key)), None

        return phantom.APP_SUCCESS, parameter

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = ERROR_CODE_MSG
                    error_msg = e.args[0]
            else:
                error_code = ERROR_CODE_MSG
                error_msg = ERROR_MSG_UNAVAILABLE
        except:
            error_code = ERROR_CODE_MSG
            error_msg = ERROR_MSG_UNAVAILABLE

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = TYPE_ERR_MSG
        except:
            error_msg = ERROR_MSG_UNAVAILABLE

        try:
            if error_code in ERROR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(
                    error_code, error_msg)
        except:
            self.debug_print("Error occurred while parsing error message")
            error_text = PARSE_ERR_MSG

        return error_text

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Attempting to connect to IronAPI")

        call_status = None

        try:
            response = self._api_instance.login(swagger_client.IronapiTypesLoginRequest(), _preload_content=False)
            self.save_progress("Received response: Code:{}, Data:{}".format(response.status, self._handle_py_ver_compat_for_input_str(response.data)))
            if response.status != 200:
                call_status = phantom.APP_ERROR
                action_result.set_status(call_status, "Fetch for Login failed. Status code was {}".format(response.status))
            else:
                call_status = phantom.APP_SUCCESS
        except ApiException as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, 'A server error has occurred: {}'.format(err))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, err)
        if phantom.is_success(call_status):
            return action_result.set_status(phantom.APP_SUCCESS, "Test Connectivity to IronAPI Passed")
        else:
            self.save_progress("Error occurred in Test Connectivity. {}".format(action_result.get_message()))
            return action_result.set_status(phantom.APP_ERROR, "Test Connectivity to IronAPI Failed")

    def _handle_irondefense_rate_alert(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Received param: {0}".format(param))
        try:
            analyst_severity = severity_mapping[self._handle_py_ver_compat_for_input_str(param.get('analyst_severity', ''))]
        except:
            message = "Please provide a valid value in the 'analyst_severity' action parameter"
            return action_result.set_status(phantom.APP_ERROR, message)
        try:
            analyst_expectation = expectation_mapping[self._handle_py_ver_compat_for_input_str(param.get('analyst_expectation', ''))]
        except:
            message = "Please provide a valid value in the 'analyst_expectation' action parameter"
            return action_result.set_status(phantom.APP_ERROR, message)
        # Access action parameters passed in the 'param' dictionary
        request = {
            'alert_id': self._handle_py_ver_compat_for_input_str(param.get('alert_id')),
            'comment': self._handle_py_ver_compat_for_input_str(param.get('comment')),
            'share_comment_with_irondome': param.get('share_comment_with_irondome', True),
            'analyst_severity': analyst_severity,
            'analyst_expectation': analyst_expectation
        }

        call_status = None

        try:
            response = self._api_instance.rate_alert(swagger_client.AlertRateAlertRequest(request), _preload_content=False)
            self.save_progress("Received response: Code:{}, Data:{}".format(response.status, self._handle_py_ver_compat_for_input_str(response.data)))
            if response.status != 200:
                call_status = phantom.APP_ERROR
                action_result.set_status(call_status, "Rate Alert failed. Status code was {}".format(response.status))
            else:
                response_data = json.loads(response.data)
                call_status = phantom.APP_SUCCESS
        except ApiException as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, 'A server error has occurred: {}'.format(err))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, err)

        if phantom.is_success(call_status):
            self.debug_print("Alert rating was successful")
            # Add the response into the data section
            action_result.add_data(response_data)
            return action_result.set_status(phantom.APP_SUCCESS, "Alert rating was successful")
        else:
            self.debug_print("Alert rating failed. {}".format(action_result.get_message()))
            return action_result.set_status(phantom.APP_ERROR, "Alert rating failed. {}".format(action_result.get_message()))

    def _handle_irondefense_set_alert_status(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Received param: {0}".format(param))
        try:
            status = status_mapping[self._handle_py_ver_compat_for_input_str(param.get('alert_status'))]
        except:
            message = "Please provide a valid value in the 'alert_status' action parameter"
            return action_result.set_status(phantom.APP_ERROR, message)
        # Access action parameters passed in the 'param' dictionary
        request = {
            'alert_id': self._handle_py_ver_compat_for_input_str(param.get('alert_id')),
            'comment': self._handle_py_ver_compat_for_input_str(param.get('comment')),
            'share_comment_with_irondome': param.get('share_comment_with_irondome', True),
            'status': status}

        call_status = None

        try:
            response = self._api_instance.set_alert_status(swagger_client.AlertSetAlertStatusRequest(request), _preload_content=False)
            self.save_progress("Received response: Code:{}, Data:{}".format(response.status, self._handle_py_ver_compat_for_input_str(response.data)))
            if response.status != 200:
                call_status = phantom.APP_ERROR
                action_result.set_status(call_status, "Set Alert status failed. Status code was {}".format(response.status))
            else:
                response_data = json.loads(response.data)
                call_status = phantom.APP_SUCCESS
        except ApiException as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, 'A server error has occurred: {}'.format(err))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, err)
        if phantom.is_success(call_status):
            self.debug_print("Setting alert status was successful")
            # Add the response into the data section
            action_result.add_data(response_data)
            return action_result.set_status(phantom.APP_SUCCESS, "Setting alert status was successful")
        else:
            self.debug_print("Setting alert status failed. {}".format(
                action_result.get_message()))
            return action_result.set_status(phantom.APP_ERROR, "Setting alert status failed. {}".format(action_result.get_message()))

    def _handle_irondefense_comment_on_alert(self, param):
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Received param: {0}".format(param))

        # Access action parameters passed in the 'param' dictionary
        request = {
            'alert_id': self._handle_py_ver_compat_for_input_str(param.get('alert_id')),
            'comment': self._handle_py_ver_compat_for_input_str(param.get('comment')),
            'share_comment_with_irondome': param.get('share_comment_with_irondome', True)
        }

        call_status = None

        try:
            response = self._api_instance.comment_on_alert(swagger_client.AlertCommentOnAlertRequest(request), _preload_content=False)
            self.save_progress("Received response: Code:{}, Data:{}".format(response.status, self._handle_py_ver_compat_for_input_str(response.data)))
            if response.status != 200:
                call_status = phantom.APP_ERROR
                action_result.set_status(call_status, "Comment on Alert failed. Status code was {}".format(response.status))
            else:
                response_data = json.loads(response.data)
                call_status = phantom.APP_SUCCESS
        except ApiException as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, 'A server error has occurred: {}'.format(err))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, err)

        if phantom.is_success(call_status):
            self.debug_print("Adding comment to alert was successful")
            # Add the response into the data section
            action_result.add_data(response_data)
            return action_result.set_status(phantom.APP_SUCCESS, "Adding comment to alert was successful")
        else:
            self.debug_print("Adding comment to alert failed. {}".format(action_result.get_message()))
            return action_result.set_status(phantom.APP_ERROR, "Adding comment failed. {}".format(action_result.get_message()))

    def _handle_irondefense_report_observed_bad_activity(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Received param: {0}".format(param))

        # Access action parameters passed in the 'param' dictionary
        request = {
            'name': self._handle_py_ver_compat_for_input_str(param['name']),
            'description': self._handle_py_ver_compat_for_input_str(param.get('description', '')),
            'domain': self._handle_py_ver_compat_for_input_str(param.get('domain', '')),
            'ip': self._handle_py_ver_compat_for_input_str(param.get('ip', '')),
            'activity_start_time': fix_timestamp(self._handle_py_ver_compat_for_input_str(param['activity_start_time'])),
            'activity_end_time': fix_timestamp(self._handle_py_ver_compat_for_input_str(param.get('activity_end_time',
                    self._handle_py_ver_compat_for_input_str(param['activity_start_time'])))),
        }

        self.save_progress("Request: {0}".format(request))

        call_status = None

        try:
            response = self._api_instance.report_observed_bad_activity(swagger_client.ThreatReportObservedBadActivityRequest(request), _preload_content=False)
            self.save_progress("Received response: Code:{}, Data:{}".format(response.status, self._handle_py_ver_compat_for_input_str(response.data)))
            if response.status != 200:
                call_status = phantom.APP_ERROR
                action_result.set_status(call_status, "Report observed bad activity failed. Status code was {}".format(response.status))
            else:
                response_data = json.loads(response.data)
                call_status = phantom.APP_SUCCESS
        except ApiException as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, 'A server error has occurred: {}'.format(err))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, err)

        if phantom.is_success(call_status):
            self.debug_print("Reporting bad activity to IronDefense was successful")
            # Add the response into the data section
            action_result.add_data(response_data)
            return action_result.set_status(phantom.APP_SUCCESS, "Reporting bad activity to IronDefense was successful")
        else:
            self.debug_print("Reporting bad activity to IronDefense failed. {}".format(action_result.get_message()))
            return action_result.set_status(phantom.APP_ERROR, "Reporting bad activity to IronDefense failed. {}".format(action_result.get_message()))

    def _handle_irondefense_get_alert_irondome_info(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Received param: {0}".format(param))

        # Access action parameters passed in the 'param' dictionary
        request = {
            'alert_id': self._handle_py_ver_compat_for_input_str(param['alert_id'])
        }

        call_status = None

        try:
            response = self._api_instance.get_alert_iron_dome_information(swagger_client.DomeGetAlertIronDomeInformationRequest(request), _preload_content=False)
            self.save_progress("Received response: Code:{}, Data:{}".format(response.status, self._handle_py_ver_compat_for_input_str(response.data)))
            if response.status != 200:
                call_status = phantom.APP_ERROR
                action_result.set_status(call_status, "Get alert IronDome info failed. Status code was {}".format(response.status))
            else:
                response_data = json.loads(response.data)
                call_status = phantom.APP_SUCCESS
        except ApiException as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, 'A server error has occurred: {}'.format(err))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, err)

        if phantom.is_success(call_status):
            self.debug_print("Retrieving IronDome alert info was successful")
            # Add the response into the data section
            action_result.add_data(response_data)
            return action_result.set_status(phantom.APP_SUCCESS, "Retrieving IronDome alert info was successful")
        else:
            self.debug_print("Retrieving IronDome alert info failed. {}".format(action_result.get_message()))
            return action_result.set_status(phantom.APP_ERROR, "Retrieving IronDome alert info failed. {}".format(action_result.get_message()))

    def _handle_irondefense_get_alert_notifications(self):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict()))

        call_status = None

        try:
            response = self._api_instance.get_alert_notifications(swagger_client.AlertGetAlertNotificationsRequest(limit=self._alert_limit), _preload_content=False)
            self.save_progress("Received response: Code:{}, Data:{}".format(response.status, self._handle_py_ver_compat_for_input_str(response.data)))
            if response.status != 200:
                call_status = phantom.APP_ERROR
                action_result.set_status(call_status, "Fetch for Alert Notifications failed. Status code was {}".format(response.status))
            else:
                response_data = json.loads(response.data)
                call_status = phantom.APP_SUCCESS
        except ApiException as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, 'A server error has occurred: {}'.format(err))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, err)

        if phantom.is_success(call_status):
            self.save_progress("Fetching alert notifications was successful")
            # Filter the response
            try:
                for alert_notification in response_data['alert_notifications']:
                    if alert_notification['alert_action'] in self._alert_notification_actions and alert_notification['alert']:
                        alert = alert_notification['alert']
                        if alert['category'] not in self._alert_categories and alert['sub_category'] not in self._alert_subcategories:
                            if self._alert_severity_lower <= int(alert['severity']) <= self._alert_severity_upper:
                                # create container
                                container = {
                                    'name': alert['id'],
                                    'kill_chain': alert['category'],
                                    'description': "IronDefense {}/{} alert".format(alert['category'], alert['sub_category']),
                                    'source_data_identifier': alert['id'],
                                    'data': alert,
                                }
                                container_status, container_msg, container_id = self.save_container(container)
                                if container_status == phantom.APP_ERROR:
                                    self.debug_print("Failed to store: {}".format(container_msg))
                                    self.debug_print("Failed with status: {}".format(container_status))
                                    action_result.set_status(phantom.APP_ERROR, 'Alert Notification container creation failed: {}'.format(container_msg))
                                    return container_status

                                # add notification as artifact of container
                                artifact = {
                                    'data': alert_notification,
                                    'name': "{} ALERT NOTIFICATION".format(alert_notification['alert_action'][4:].replace("_", " ")),
                                    'container_id': container_id,
                                    'source_data_identifier': "{}-{}".format(alert['id'], alert["updated"]),
                                    'start_time': alert['updated']
                                }
                                artifact_status, artifact_msg, artifact_id = self.save_artifact(artifact)
                                if artifact_status == phantom.APP_ERROR:
                                    self.debug_print("Failed to store: {}".format(artifact_msg))
                                    self.debug_print("Failed with status: {}".format(artifact_status))
                                    action_result.set_status(phantom.APP_ERROR, 'Alert Notification artifact creation failed: {}'.format(artifact_msg))
                                    return artifact_status
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing response from server. {}".format(err))

            self.save_progress("Filtering alert notifications was successful")
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            self.debug_print(action_result.get_message())
            self.save_progress("Fetching alert notifications failed")
            return action_result.set_status(phantom.APP_ERROR, action_result.get_message())

    def _handle_irondefense_get_dome_notifications(self):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict()))

        call_status = None

        try:
            response = self._api_instance.get_dome_notifications(swagger_client.DomeGetDomeNotificationsRequest(limit=self._dome_limit), _preload_content=False)
            self.save_progress("Received response: Code:{}, Data:{}".format(response.status, self._handle_py_ver_compat_for_input_str(response.data)))
            if response.status != 200:
                call_status = phantom.APP_ERROR
                action_result.set_status(call_status, "Fetch for Dome Notifications failed. Status code was {}".format(response.status))
            else:
                response_data = json.loads(response.data)
                call_status = phantom.APP_SUCCESS
        except ApiException as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, 'A server error has occurred: {}'.format(err))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, err)

        if phantom.is_success(call_status):
            self.save_progress("Fetching dome notifications was successful")
            # Filter the response
            try:
                for dome_notification in response_data['dome_notifications']:
                    if dome_notification['category'] not in self._dome_categories:
                        for alert_id in dome_notification['alert_ids']:
                            # create or find container
                            container = {
                                'name': alert_id,
                                'source_data_identifier': alert_id,
                            }
                            container_status, container_msg, container_id = self.save_container(container)
                            if container_status == phantom.APP_ERROR:
                                self.debug_print("Failed to store: {}".format(container_msg))
                                self.debug_print("Failed with status: {}".format(container_status))
                                action_result.set_status(phantom.APP_ERROR, 'Dome Notification container creation failed: {}'.format(container_msg))
                                return container_status

                            # add notification as artifact of container
                            artifact = {
                                'data': dome_notification,
                                'name': "{} DOME NOTIFICATION".format(dome_notification['category'][4:].replace("_", " ")),
                                'container_id': container_id,
                                'source_data_identifier': "{}".format(dome_notification["id"]),
                                'start_time': dome_notification['created']
                            }
                            artifact_status, artifact_msg, artifact_id = self.save_artifact(artifact)
                            if artifact_status == phantom.APP_ERROR:
                                self.debug_print("Failed to store: {}".format(artifact_msg))
                                self.debug_print("Failed with status: {}".format(artifact_status))
                                action_result.set_status(phantom.APP_ERROR, 'Dome Notification artifact creation failed: {}'.format(artifact_msg))
                                return artifact_status
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing response from server. {}".format(err))
            self.save_progress("Filtering dome notifications was successful")
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            self.debug_print(action_result.get_message())
            self.save_progress("Fetching dome notifications failed")
            return action_result.set_status(phantom.APP_ERROR, action_result.get_message())

    def _handle_irondefense_get_event_notifications(self):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict()))

        call_status = None

        try:
            response = self._api_instance.get_event_notifications(swagger_client.EventGetEventNotificationsRequest(limit=self._event_limit), _preload_content=False)
            self.save_progress("Received response: Code:{}, Data:{}".format(response.status, self._handle_py_ver_compat_for_input_str(response.data)))
            if response.status != 200:
                call_status = phantom.APP_ERROR
                action_result.set_status(call_status, "Fetch for Event Notifications failed. Status code was {}".format(response.status))
            else:
                response_data = json.loads(response.data)
                call_status = phantom.APP_SUCCESS
        except ApiException as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, 'A server error has occurred: {}'.format(err))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, err)

        if response.status != 200:
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, "Fetch for EventNotifications failed. Status code was {}".format(response.status))

        if phantom.is_success(call_status):
            self.save_progress("Fetching event notifications was successful")
            # Filter the response
            try:
                for event_notification in response_data['event_notifications']:
                    if event_notification['event_action'] in self._event_notification_actions and event_notification['event']:
                        event = event_notification['event']
                        if event['category'] not in self._event_categories and event['sub_category'] not in self._event_subcategories:
                            if self._event_severity_lower <= int(event['severity']) <= self._event_severity_upper:
                                if self._store_event_notifs_in_alert_containers:
                                    # store in alert container
                                    container = {
                                        'name': event['alert_id'],
                                        'source_data_identifier': event['alert_id'],
                                    }
                                    container_status, container_msg, container_id = self.save_container(container)
                                    if container_status == phantom.APP_ERROR:
                                        self.debug_print("Failed to store: {}".format(container_msg))
                                        self.debug_print("Failed with status: {}".format(container_status))
                                        action_result.set_status(phantom.APP_ERROR, 'Event Notification container creation failed: {}'.format(container_msg))
                                        return container_status

                                    # add notification as artifact of container
                                    artifact = {
                                        'data': event_notification,
                                        'name': "{} EVENT NOTIFICATION".format(event_notification['event_action'][4:].replace("_", " ")),
                                        'container_id': container_id,
                                        'source_data_identifier': "{}-{}".format(event['id'], event["updated"]),
                                        'start_time': event['updated']
                                    }
                                else:
                                    # store in event container
                                    container = {
                                        'name': event['id'],
                                        'kill_chain': event['category'],
                                        'description': "IronDefense {}/{} event".format(event['category'], event['sub_category']),
                                        'source_data_identifier': event['id'],
                                        'data': event,
                                    }
                                    container_status, container_msg, container_id = self.save_container(container)
                                    if container_status == phantom.APP_ERROR:
                                        self.debug_print("Failed to store: {}".format(container_msg))
                                        self.debug_print("Failed with status: {}".format(container_status))
                                        action_result.set_status(phantom.APP_ERROR, 'Event Notification container creation failed: {}'.format(container_msg))
                                        return container_status

                                    # add notification as artifact of container
                                    artifact = {
                                        'data': event_notification,
                                        'name': "{} EVENT NOTIFICATION".format(event_notification['event_action'][4:].replace("_", " ")),
                                        'container_id': container_id,
                                        'source_data_identifier': "{}-{}".format(event['id'], event["updated"]),
                                        'start_time': event['updated']
                                    }
                                artifact_status, artifact_msg, artifact_id = self.save_artifact(artifact)
                                if artifact_status == phantom.APP_ERROR:
                                    self.debug_print("Failed to store: {}".format(artifact_msg))
                                    self.debug_print("Failed with status: {}".format(artifact_status))
                                    action_result.set_status(phantom.APP_ERROR, 'Event Notification artifact creation failed: {}'.format(artifact_msg))
                                    return artifact_status
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing response from server. {}".format(err))
            self.save_progress("Filtering event notifications was successful")
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            self.debug_print(action_result.get_message())
            self.save_progress("Fetching event notifications failed")
            return action_result.set_status(phantom.APP_ERROR, action_result.get_message())

    def _handle_irondefense_get_alerts(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Received param: {0}".format(param))

        # Access action parameters passed in the 'param' dictionary
        request = {}
        if 'alert_id' in param and self._handle_py_ver_compat_for_input_str(param['alert_id']).strip() != '':
            request['alert_id'] = self._handle_py_ver_compat_for_input_str(param['alert_id']).strip().split(",")
        if 'category' in param and self._handle_py_ver_compat_for_input_str(param['category']).strip() != '':
            request['category'] = [cat.strip().replace(" ", "_").upper() for cat in self._handle_py_ver_compat_for_input_str(param['category']).split(',')]
        if 'sub_category' in param and self._handle_py_ver_compat_for_input_str(param['sub_category']).strip() != '':
            request['sub_category'] = [cat.strip().replace(" ", "_").upper() for cat in self._handle_py_ver_compat_for_input_str(param['sub_category']).split(',')]
        try:
            if 'status' in param and self._handle_py_ver_compat_for_input_str(param['status']).strip() != '':
                request['status'] = [status_mapping[status.strip().lower()]for status in self._handle_py_ver_compat_for_input_str(param['status']).split(',')]
        except:
            message = "Please provide a valid value in the 'status' action parameter"
            return action_result.set_status(phantom.APP_ERROR, message)

        min_sev = 0
        max_sev = 1000

        if 'min_severity' in param:
            ret_val, min_sev = self._validate_integer(action_result, param['min_severity'], MIN_SEVERITY_KEY)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        if 'max_severity' in param:
            ret_val, max_sev = self._validate_integer(action_result, param['max_severity'], MAX_SEVERITY_KEY)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        request['severity'] = {
            "lower_bound": min_sev,
            "upper_bound": max_sev
        }

        call_status = None

        try:
            response = self._api_instance.get_alerts(swagger_client.AlertGetAlertsRequest(request), _preload_content=False)
            self.save_progress("Received response: Code:{}, Data:{}".format(response.status, self._handle_py_ver_compat_for_input_str(response.data)))
            if response.status != 200:
                call_status = phantom.APP_ERROR
                action_result.set_status(call_status, "Get Alerts failed. Status code was {}".format(response.status))
            else:
                response_data = json.loads(response.data)
                call_status = phantom.APP_SUCCESS
        except ApiException as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, 'A server error has occurred: {}'.format(err))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, err)

        if phantom.is_success(call_status):
            self.debug_print("Retrieving alerts was successful")
            # Add the response into the data section
            action_result.add_data(response_data)
            return action_result.set_status(phantom.APP_SUCCESS, "Retrieving alerts was successful")
        else:
            self.debug_print("Retrieving alerts failed. {}".format(action_result.get_message()))
            return action_result.set_status(phantom.APP_ERROR, "Retrieving alerts failed. {}".format(action_result.get_message()))

    def _handle_irondefense_get_events(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        request = {
            'alert_id': self._handle_py_ver_compat_for_input_str(param['alert_id'])
        }

        call_status = None

        try:
            response = self._api_instance.get_events(swagger_client.EventGetEventsRequest(request), _preload_content=False)
            self.save_progress("Received response: Code:{}, Data:{}".format(response.status, self._handle_py_ver_compat_for_input_str(response.data)))
            if response.status != 200:
                call_status = phantom.APP_ERROR
                action_result.set_status(call_status, "Get Events failed. Status code was {}".format(response.status))
            else:
                response_data = json.loads(response.data)
                call_status = phantom.APP_SUCCESS
        except ApiException as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, 'A server error has occurred: {}'.format(err))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, err)

        if phantom.is_success(call_status):
            self.debug_print("Retrieving events was successful")
            # Add the response into the data section
            action_result.add_data(response_data)
            return action_result.set_status(phantom.APP_SUCCESS, "Retrieving events was successful")
        else:
            self.debug_print("Retrieving events failed. {}".format(action_result.get_message()))
            return action_result.set_status(phantom.APP_ERROR, "Retrieving events failed. {}".format(action_result.get_message()))

    def _handle_irondefense_get_event(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        request = {
            'event_id': self._handle_py_ver_compat_for_input_str(param['event_id'])
        }

        call_status = None

        try:
            response = self._api_instance.get_event(swagger_client.EventGetEventRequest(request), _preload_content=False)
            self.save_progress("Received response: Code:{}, Data:{}".format(response.status, self._handle_py_ver_compat_for_input_str(response.data)))
            if response.status != 200:
                call_status = phantom.APP_ERROR
                action_result.set_status(call_status, "Get Event failed. Status code was {}".format(response.status))
            else:
                response_data = json.loads(response.data)
                call_status = phantom.APP_SUCCESS
        except ApiException as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, 'A server error has occurred: {}'.format(err))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            call_status = phantom.APP_ERROR
            action_result.set_status(call_status, err)

        if phantom.is_success(call_status):
            self.debug_print("Retrieving event was successful")
            # Add the response into the data section
            action_result.add_data(response_data)
            return action_result.set_status(phantom.APP_SUCCESS, "Retrieving event was successful")
        else:
            self.debug_print("Retrieving event failed. {}".format(action_result.get_message()))
            return action_result.set_status(phantom.APP_ERROR, "Retrieving event failed. {}".format(action_result.get_message()))

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)
        elif action_id == 'irondefense_rate_alert':
            ret_val = self._handle_irondefense_rate_alert(param)
        elif action_id == 'irondefense_set_alert_status':
            ret_val = self._handle_irondefense_set_alert_status(param)
        elif action_id == 'irondefense_comment_on_alert':
            ret_val = self._handle_irondefense_comment_on_alert(param)
        elif action_id == 'irondefense_report_observed_bad_activity':
            ret_val = self._handle_irondefense_report_observed_bad_activity(param)
        elif action_id == 'irondefense_get_alert_irondome_info':
            ret_val = self._handle_irondefense_get_alert_irondome_info(param)
        elif action_id == 'irondefense_get_events':
            ret_val = self._handle_irondefense_get_events(param)
        elif action_id == 'on_poll':
            alert_ret_val = phantom.APP_SUCCESS
            dome_ret_val = phantom.APP_SUCCESS
            event_ret_val = phantom.APP_SUCCESS

            if self._enable_alert_notifications:
                alert_ret_val = self._handle_irondefense_get_alert_notifications()
            else:
                self.save_progress("Fetching alert notifications is disabled")
            if self._enable_dome_notifications:
                dome_ret_val = self._handle_irondefense_get_dome_notifications()
            else:
                self.save_progress("Fetching dome notifications is disabled")
            if self._enable_event_notifications:
                event_ret_val = self._handle_irondefense_get_event_notifications()
            else:
                self.save_progress("Fetching event notifications is disabled")
            ret_val = alert_ret_val and dome_ret_val and event_ret_val
        elif action_id == 'irondefense_get_alerts':
            ret_val = self._handle_irondefense_get_alerts(param)
        elif action_id == 'irondefense_get_event':
            ret_val = self._handle_irondefense_get_event(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version.")

        # get the asset config
        config = self.get_config()

        self._base_url = self._handle_py_ver_compat_for_input_str(config.get('base_url'))
        self._username = self._handle_py_ver_compat_for_input_str(config.get('username'))
        self._password = config.get('password')
        self._verify_server_cert = config.get('verify_server_cert', True)

        configuration = swagger_client.Configuration()
        configuration.host = self._handle_py_ver_compat_for_input_str(config.get('base_url'))
        configuration.username = self._handle_py_ver_compat_for_input_str(config.get('username'))
        configuration.password = config.get('password')
        configuration.verify_ssl = config.get('verify_server_cert', True)
        self._api_instance = swagger_client.IronApiApi(swagger_client.ApiClient(configuration))

        # Alert Notification Configs
        self._enable_alert_notifications = config.get('enable_alert_notifications', True)
        if self._enable_alert_notifications:
            alert_acts = self._handle_py_ver_compat_for_input_str(config.get('alert_notification_actions'))
            if alert_acts:
                self._alert_notification_actions = ["ANA_ {}".format(act.strip().replace(" ", "_").upper()) for act in alert_acts.split(',') if act.strip()]
            else:
                self._alert_notification_actions = ["ANA_ALERT_CREATED"]
            alert_cats = self._handle_py_ver_compat_for_input_str(config.get('alert_categories'))
            if alert_cats:
                self._alert_categories = [cat.strip().replace(" ", "_").upper() for cat in alert_cats.split(',') if cat.strip()]
            else:
                self._alert_categories = []
            alert_subcats = self._handle_py_ver_compat_for_input_str(config.get('alert_subcategories'))
            if alert_subcats:
                self._alert_subcategories = [subcat.strip().replace(" ", "_").upper() for subcat in alert_subcats.split(',') if subcat.strip()]
            else:
                self._alert_subcategories = []
            ret_val, self._alert_severity_lower = self._validate_integer(self, config.get('alert_severity_lower'), ALERT_SEVERITY_LOWER_KEY)
            if(phantom.is_fail(ret_val)):
                return self.get_status()

            ret_val, self._alert_severity_upper = self._validate_integer(self, config.get('alert_severity_upper'), ALERT_SEVERITY_UPPER_KEY)
            if(phantom.is_fail(ret_val)):
                return self.get_status()

            if self._alert_severity_lower >= self._alert_severity_upper:
                self.save_progress("Initialization Failed: Invalid Range for Alert Severity- {} is not lower than {}".format(self._alert_severity_lower,
                 self._alert_severity_upper))
                return phantom.APP_ERROR
            ret_val, self._alert_limit = self._validate_integer(self, config.get('alert_limit'), ALERT_LIMIT_KEY)
            if(phantom.is_fail(ret_val)):
                return self.get_status()

        # Dome Notification Configs
        self._enable_dome_notifications = config.get('enable_dome_notifications', False)
        if self._enable_dome_notifications:
            dome_cats = self._handle_py_ver_compat_for_input_str(config.get('dome_categories'))
            if dome_cats:
                self._dome_categories = ["DNC_{}".format(cat.strip().replace(" ", "_").upper()) for cat in dome_cats.split(',') if cat.strip()]
            else:
                self._dome_categories = []
            ret_val, self._dome_limit = self._validate_integer(self, config.get('dome_limit'), DOME_LIMIT_KEY)
            if(phantom.is_fail(ret_val)):
                return self.get_status()

        # Event Notification Configs
        self._enable_event_notifications = config.get('enable_event_notifications', False)
        if self._enable_event_notifications:
            event_acts = self._handle_py_ver_compat_for_input_str(config.get('event_notification_actions'))
            if event_acts:
                self._event_notification_actions = ["ENA_ {}".format(act.strip().replace(" ", "_").upper()) for act in event_acts.split(',') if act.strip()]
            else:
                self._event_notification_actions = ["ENA_EVENT_CREATED"]
            event_cats = self._handle_py_ver_compat_for_input_str(config.get('event_categories'))
            if event_cats:
                self._event_categories = [cat.strip().replace(" ", "_").upper() for cat in event_cats.split(',') if cat.strip()]
            else:
                self._event_categories = []
            event_subcats = self._handle_py_ver_compat_for_input_str(config.get('event_subcategories'))
            if event_subcats:
                self._event_subcategories = [subcat.strip().replace(" ", "_").upper() for subcat in event_subcats.split(',') if subcat.strip()]
            else:
                self._event_subcategories = []
            ret_val, self._event_severity_lower = self._validate_integer(self, config.get('event_severity_lower'), EVENT_SEVERITY_LOWER_KEY)
            if(phantom.is_fail(ret_val)):
                return self.get_status()

            ret_val, self._event_severity_upper = self._validate_integer(self, config.get('event_severity_upper'), EVENT_SEVERITY_UPPER_KEY)
            if(phantom.is_fail(ret_val)):
                return self.get_status()

            if self._event_severity_lower >= self._event_severity_upper:
                self.save_progress("Initialization Failed: Invalid Range for Event Severity- {} is not lower than {}".format(self._event_severity_lower,
                self._event_severity_upper))
                return phantom.APP_ERROR

            ret_val, self._event_limit = self._validate_integer(self, config.get('event_limit'), EVENT_LIMIT_KEY)
            if(phantom.is_fail(ret_val)):
                return self.get_status()

            self._store_event_notifs_in_alert_containers = config.get('store_event_notifs_in_alert_containers', True)

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = IronnetConnector()
        connector.print_progress_message = True

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
