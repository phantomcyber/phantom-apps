#
# Copyright (c) 2020 Digital Shadows Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

import phantom.app as phantom

from digital_shadows_consts import DS_API_KEY_CFG, DS_API_SECRET_KEY_CFG
from digital_shadows_consts import DS_TEST_CONNECTIVITY_MSG
from digital_shadows_consts import DS_TEST_CONNECTIVITY_MSG_PASS
from digital_shadows_consts import DS_TEST_CONNECTIVITY_MSG_FAIL

from dsapi.service.ds_base_service import DSBaseService
from bs4 import UnicodeDammit


class DSTestConnectivityConnector(object):

    def __init__(self, connector):
        """
        :param connector: DigitalShadowsConnector
        """
        self._connector = connector

        config = connector.get_config()
        self._ds_api_key = UnicodeDammit(config[DS_API_KEY_CFG]).unicode_markup.encode('utf-8')
        self._ds_api_secret_key = config[DS_API_SECRET_KEY_CFG]

    def test_connectivity(self):
        self._connector.save_progress(DS_TEST_CONNECTIVITY_MSG.format(self._ds_api_key))

        ds_service = DSBaseService(self._ds_api_key, self._ds_api_secret_key)
        if ds_service.valid_credentials():
            return self._connector.set_status(phantom.APP_SUCCESS, DS_TEST_CONNECTIVITY_MSG_PASS)
        else:
            return self._connector.set_status(phantom.APP_ERROR, DS_TEST_CONNECTIVITY_MSG_FAIL)
