# File: sixgill_test_connectivity_connector.py
#
# Copyright (c) 2021 Cybersixgill Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

import phantom.app as phantom

# Sixgill Libraries
from sixgill.sixgill_base_client import SixgillBaseClient
from sixgill.sixgill_exceptions import AuthException

from sixgilldarkfeed_consts import *
from phantom.action_result import ActionResult


class SixgillTestConnectivityConnector(object):
    def __init__(self, connector):
        """
        :param connector: SIXGILL
        """
        self._connector = connector

        config = connector.get_config()
        self._sixgill_client_id = config[SIXGILL_API_ID_CFG]
        self._sixgill_api_secret_key = config[SIXGILL_API_SECRET_KEY_CFG]
        self._sixgill_phantom_channel_id = SIXGILL_CHANNEL_ID

    def test_connectivity(self):
        action_result = self._connector.add_action_result(ActionResult(dict()))
        self._connector.save_progress(SIXGILL_TEST_CONNECTIVITY_MSG)
        sixgill_valid_credentials = SixgillBaseClient(
            self._sixgill_client_id, self._sixgill_api_secret_key, self._sixgill_phantom_channel_id
        )
        try:
            if sixgill_valid_credentials._get_access_token():
                self._connector.save_progress(SIXGILL_TEST_CONNECTIVITY_MSG_PASS)
                return action_result.set_status(phantom.APP_SUCCESS, SIXGILL_TEST_CONNECTIVITY_MSG_PASS)
            return action_result.set_status(phantom.APP_ERROR, SIXGILL_TEST_CONNECTIVITY_MSG_FAIL)
        except AuthException:
            return action_result.set_status(phantom.APP_ERROR, SIXGILL_TEST_CONNECTIVITY_MSG_FAIL)
        except Exception as e:
            err = self._connector._get_error_message_from_exception(e)
            self._connector.debug_print("Error message: {}".format(err))
            return action_result.set_status(phantom.APP_ERROR, SIXGILL_TEST_CONNECTIVITY_MSG_FAIL)
