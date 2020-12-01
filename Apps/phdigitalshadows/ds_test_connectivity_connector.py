# File: ds_test_connectivity_connector.py
# Copyright (c) 2020 Digital Shadows Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

import phantom.app as phantom

from digital_shadows_consts import *

from dsapi.service.ds_base_service import DSBaseService


class DSTestConnectivityConnector(object):

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

    def test_connectivity(self):
        self._connector.save_progress(DS_TEST_CONNECTIVITY_MSG.format(self._ds_api_key))

        try:
            ds_service = DSBaseService(self._ds_api_key, self._ds_api_secret_key)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return self._connector.set_status(phantom.APP_ERROR, "{0} {1}".format(SERVICE_ERR_MSG, error_message))
        try:
            if ds_service.valid_credentials():
                return self._connector.set_status(phantom.APP_SUCCESS, DS_TEST_CONNECTIVITY_MSG_PASS)
            else:
                return self._connector.set_status(phantom.APP_ERROR, DS_TEST_CONNECTIVITY_MSG_FAIL)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return self._connector.set_status(phantom.APP_ERROR, "{0}. {1}".format(DS_TEST_CONNECTIVITY_MSG_FAIL, error_message))
