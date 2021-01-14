#
# Copyright (c) 2020 Cybersixgill Ltd.
#

import phantom.app as phantom

# Sixgill Libraries
from sixgill.sixgill_base_client import SixgillBaseClient
from sixgill.sixgill_exceptions import AuthException

# Usage of the consts file is recommended
from sixgilldarkfeed_consts import SIXGILL_API_ID_CFG, SIXGILL_API_SECRET_KEY_CFG
from sixgilldarkfeed_consts import SIXGILL_CHANNEL_ID, SIXGILL_TEST_CONNECTIVITY_MSG
from sixgilldarkfeed_consts import SIXGILL_TEST_CONNECTIVITY_MSG_PASS, SIXGILL_TEST_CONNECTIVITY_MSG_FAIL


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
        self._connector.save_progress(SIXGILL_TEST_CONNECTIVITY_MSG)
        sixgill_valid_credentials = SixgillBaseClient(
            self._sixgill_client_id, self._sixgill_api_secret_key, self._sixgill_phantom_channel_id
        )
        try:
            if sixgill_valid_credentials._get_access_token():
                self._connector.save_progress(SIXGILL_TEST_CONNECTIVITY_MSG_PASS)
                return self._connector.set_status(phantom.APP_SUCCESS, SIXGILL_TEST_CONNECTIVITY_MSG_PASS)
        except AuthException:
            return self._connector.set_status(phantom.APP_ERROR, SIXGILL_TEST_CONNECTIVITY_MSG_FAIL)
