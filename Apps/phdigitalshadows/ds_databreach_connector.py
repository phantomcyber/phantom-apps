# File: ds_databreach_connector.py
# Copyright (c) 2020 Digital Shadows Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

import phantom.app as phantom
from phantom.action_result import ActionResult

from digital_shadows_consts import *

from dsapi.service.data_breach_service import DataBreachService
from dsapi.service.data_breach_record_service import DataBreachRecordService


class DSDataBreachConnector(object):

    def __init__(self, connector):
        """
        :param connector: DigitalShadowsConnector
        """
        self._connector = connector

        config = connector.get_config()
        self._ds_api_key = config[DS_API_KEY_CFG]
        self._ds_api_secret_key = config[DS_API_SECRET_KEY_CFG]

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
                    error_code = ERR_CODE_MSG
                    error_msg = e.args[0]
            else:
                error_code = ERR_CODE_MSG
                error_msg = ERR_MSG_UNAVAILABLE
        except:
            error_code = ERR_CODE_MSG
            error_msg = ERR_MSG_UNAVAILABLE

        try:
            if error_code in ERR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
        except:
            self.debug_print(PARSE_ERR_MSG)
            error_text = PARSE_ERR_MSG

        return error_text

    def _validate_integer(self, action_result, parameter, key):
        if parameter:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MSG.format(key=key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MSG.format(key=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, NON_NEGATIVE_INTEGER_MSG.format(key=key)), None

        return phantom.APP_SUCCESS, parameter

    def get_data_breach_by_id(self, param):
        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)
        try:
            breach_service = DataBreachService(self._ds_api_key, self._ds_api_secret_key)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "{0} {1}".format(SERVICE_ERR_MSG, error_message))

        breach_id = param['breach_id']
        # validate 'breach_id' action parameter
        ret_val, breach_id = self._validate_integer(action_result, breach_id, BREACH_ID_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        try:
            breach = breach_service.find_data_breach_by_id(breach_id)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {0}".format(error_message))

        if 'id' in breach:
            summary = {
                'data_breach_count': 1,
                'data_breach_found': True
            }
            action_result.update_summary(summary)
            action_result.add_data(breach)
            action_result.set_status(phantom.APP_SUCCESS, DS_GET_BREACH_SUCCESS)
        else:
            summary = {
                'data_breach_count': 0,
                'data_breach_found': False
            }
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS, DS_GET_BREACH_NOT_FOUND)
        return action_result.get_status()

    def get_data_breach(self, param):
        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)

        date_range = param['date_range']
        param_reposted_credentials = None if 'reposted_credentials' not in param else param['reposted_credentials'].split(',')
        param_severities = None if 'severities' not in param else param.get('severities').split(',')
        param_statuses = None if 'statuses' not in param else param.get('statuses').split(',')
        param_user_name = None if 'user_name' not in param else param.get('user_name').split(',')

        try:
            breach_service = DataBreachService(self._ds_api_key, self._ds_api_secret_key)
            breach_view = DataBreachService.data_breach_view(published=date_range, reposted_credentials=param_reposted_credentials,
                                                             severities=param_severities, statuses=param_statuses, username=param_user_name)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "{0} {1}".format(SERVICE_ERR_MSG, error_message))
        try:
            breach_pages = breach_service.find_all_pages(view=breach_view)
            breach_total = len(breach_pages)
        except StopIteration:
            error_message = 'No DataBreach objects retrieved from the Digital Shadows API in page groups'
            return action_result.set_status(phantom.APP_ERROR, "Error Details: {0}".format(error_message))
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {}".format(error_message))
        if breach_total > 0:
            summary = {
                'data_breach_count': breach_total,
                'data_breach_found': True
            }
            action_result.update_summary(summary)

            for breach_page in breach_pages:
                for breach in breach_page:
                    # self._connector.save_progress('breach: ' + str(breach))
                    action_result.add_data(breach.payload)
            action_result.set_status(phantom.APP_SUCCESS, DS_GET_BREACH_SUCCESS)
        else:
            summary = {
                'data_breach_count': 0,
                'data_breach_found': False
            }
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS, DS_GET_BREACH_NOT_FOUND)
        return action_result.get_status()

    def get_data_breach_record(self, param):
        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)

        date_range = param['date_range']
        if 'domain_names' in param:
            param_domain_names = param['domain_names'].split(',')
        else:
            param_domain_names = None

        if 'review_statuses' in param:
            param_review_statuses = param['review_statuses'].split(',')
        else:
            param_review_statuses = None

        param_distinction = None if 'distinction' not in param else param.get('distinction')
        param_user_name = None if 'user_name' not in param else param.get('user_name')
        param_password = None if 'password' not in param else param.get('password')

        try:
            breach_record_service = DataBreachRecordService(self._ds_api_key, self._ds_api_secret_key)
            breach_record_view = DataBreachRecordService.data_breach_records_view(published=date_range, domain_names=param_domain_names, username=param_user_name,
                                                             password=param_password, review_statuses=param_review_statuses, distinction=param_distinction)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "{0} {1}".format(SERVICE_ERR_MSG, error_message))
        self._connector.save_progress(str(breach_record_view))
        try:
            breach_record_pages = breach_record_service.read_all_records(view=breach_record_view)
            breach_record_total = len(breach_record_pages)
        except StopIteration:
            error_message = 'No DataBreach objects retrieved from the Digital Shadows API in page groups'
            return action_result.set_status(phantom.APP_ERROR, "Error Details: {0}".format(error_message))
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {}".format(error_message))
        if breach_record_total > 0:
            summary = {
                'data_breach_record_count': breach_record_total,
                'data_breach_record_found': True
            }
            action_result.update_summary(summary)
            for breach_record_page in breach_record_pages:
                for breach_record in breach_record_page:
                    action_result.add_data(breach_record.payload)
            action_result.set_status(phantom.APP_SUCCESS, "Digital Shadows data breach records fetched")
        else:
            summary = {
                'data_breach_record_count': 0,
                'data_breach_record_found': False
            }
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS, "Data breach record not found in Digital Shadows")
        return action_result.get_status()

    def get_data_breach_record_by_id(self, param):
        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)
        try:
            breach_record_service = DataBreachRecordService(self._ds_api_key, self._ds_api_secret_key)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "{0} {1}".format(SERVICE_ERR_MSG, error_message))
        breach_id = param['breach_id']
        # validate 'breach_id' action parameter
        ret_val, breach_id = self._validate_integer(action_result, breach_id, BREACH_ID_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        try:
            breach_record_pages = breach_record_service.find_all_pages(breach_id)
            breach_record_total = len(breach_record_pages)
        except StopIteration:
            error_message = 'No data breach record retrieved from the Digital Shadows API in page groups'
            return action_result.set_status(phantom.APP_ERROR, "Error Details: {0}".format(error_message))
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {}".format(error_message))
        if breach_record_total > 0:
            summary = {
                'data_breach_record_count': breach_record_total,
                'data_breach_record_found': True
            }
            action_result.update_summary(summary)
            for breach_record_page in breach_record_pages:
                for breach_record in breach_record_page:
                    action_result.add_data(breach_record.payload)
            action_result.set_status(phantom.APP_SUCCESS, "Digital Shadows data breach records fetched")
        else:
            summary = {
                'data_breach_record_count': 0,
                'data_breach_record_found': False
            }
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS, "Data breach record not found in Digital Shadows")
        return action_result.get_status()

    def get_data_breach_record_by_username(self, param):
        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)

        try:
            breach_record_service = DataBreachRecordService(self._ds_api_key, self._ds_api_secret_key)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "{0} {1}".format(SERVICE_ERR_MSG, error_message))

        user_name = param['user_name']
        domain_names_param = None if 'domain_names' not in param else param['domain_names'].split(',')
        review_statuses_param = None if 'review_statuses' not in param else param['review_statuses'].split(',')
        published_date_range = 'ALL' if 'published_date_range' not in param else param['published_date_range']

        try:
            breach_record_view = DataBreachRecordService.data_breach_records_view(username=user_name, published=published_date_range,
                                                                domain_names=domain_names_param, review_statuses=review_statuses_param)
            self._connector.save_progress("Breach record View: {}".format(breach_record_view))
            breach_record_pages = breach_record_service.read_all_records(view=breach_record_view)
        except StopIteration:
            error_message = 'No DataBreach objects retrieved from the Digital Shadows API in page groups'
            return action_result.set_status(phantom.APP_ERROR, "Error Details: {0}".format(error_message))
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {}".format(error_message))

        breach_record_total = len(breach_record_pages)
        if breach_record_total > 0:
            summary = {
                'data_breach_record_count': breach_record_total,
                'data_breach_record_found': True
            }
            action_result.update_summary(summary)
            for breach_record_page in breach_record_pages:
                for breach_record in breach_record_page:
                    action_result.add_data(breach_record.payload)
            action_result.set_status(phantom.APP_SUCCESS, "Digital Shadows data breach records fetched")
        else:
            summary = {
                'data_breach_record_count': 0,
                'data_breach_record_found': False
            }
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS, "Data breach record not found in Digital Shadows")
        return action_result.get_status()

    def get_data_breach_record_reviews(self, param):
        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)
        try:
            breach_record_service = DataBreachRecordService(self._ds_api_key, self._ds_api_secret_key)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "{0} {1}".format(SERVICE_ERR_MSG, error_message))
        breach_record_id = param['breach_record_id']
        # validate 'breach_record_id' action parameter
        ret_val, breach_record_id = self._validate_integer(action_result, breach_record_id, BREACH_RECORD_ID_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        try:
            breach_record_reviews = breach_record_service.find_data_breach_record_reviews(breach_record_id)
            breach_record_reviews_total = len(breach_record_reviews)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {0}".format(error_message))
        if breach_record_reviews_total > 0:
            summary = {
              'breach_record_reviews_count': breach_record_reviews_total,
              'breach_record_reviews_found': True
            }
            action_result.update_summary(summary)
            for breach_record_review in breach_record_reviews:
                action_result.add_data(breach_record_review)
            action_result.set_status(phantom.APP_SUCCESS, "Digital Shadows breach record reviews fetched for the Breach Record ID: {}".format(breach_record_id))
        return action_result.get_status()

    def post_breach_record_review(self, param):
        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)
        try:
            breach_record_service = DataBreachRecordService(self._ds_api_key, self._ds_api_secret_key)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "{0} {1}".format(SERVICE_ERR_MSG, error_message))
        post_data = {
          'note': param.get('review_note'),
          'status': param.get('review_status')
        }
        breach_record_id = param.get('breach_record_id')
        # validate 'breach_record_id' action parameter
        ret_val, breach_record_id = self._validate_integer(action_result, breach_record_id, BREACH_RECORD_ID_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        try:
            response = breach_record_service.post_data_breach_record_review(post_data, breach_record_id=breach_record_id)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {0}".format(error_message))
        summary = {
          'breach_record_reviews_status_code': response['status'],
          'breach_record_reviews_message': response['message']
        }
        action_result.update_summary(summary)
        if response['message'] == "SUCCESS":
            action_result.set_status(phantom.APP_SUCCESS, "Digital Shadows breach record review posted successfully")
        else:
            action_result.set_status(phantom.APP_SUCCESS, "Error in breach record review post request")
