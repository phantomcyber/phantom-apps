# File: ds_lookup_username_connector.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

import phantom.app as phantom
from phantom.action_result import ActionResult


from digital_shadows_consts import DS_API_KEY_CFG, DS_API_SECRET_KEY_CFG
from digital_shadows_consts import DS_LOOKUP_USERNAME_SUCCESS, DS_LOOKUP_USERNAME_NOT_FOUND

from dsapi.service.data_breach_username_service import DataBreachUsernameService


class DSLookupUsernameConnector(object):

    def __init__(self, connector):
        """
        :param connector: DigitalShadowsConnector
        """
        self._connector = connector

        config = connector.get_config()
        self._ds_api_key = config[DS_API_KEY_CFG]
        self._ds_api_secret_key = config[DS_API_SECRET_KEY_CFG]

    def lookup_username(self, param):
        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)

        username_to_lookup = param.get('username')

        username_service = DataBreachUsernameService(self._ds_api_key, self._ds_api_secret_key)
        view = username_service.data_breach_username_view(username=username_to_lookup)

        found_username = next((data_breach_username
                               for data_breach_username in username_service.find_all(view=view)
                               if data_breach_username.username == username_to_lookup),
                              None)

        if found_username is not None:
            summary, data = self._lookup_success(username_to_lookup, found_username)
            action_result.update_summary(summary)
            action_result.add_data(data)
            action_result.set_status(phantom.APP_SUCCESS, DS_LOOKUP_USERNAME_SUCCESS)
        else:
            summary, data = self._lookup_failure(username_to_lookup)
            action_result.update_summary(summary)
            action_result.add_data(data)
            action_result.set_status(phantom.APP_SUCCESS, DS_LOOKUP_USERNAME_NOT_FOUND)

        return action_result.get_status()

    def _lookup_success(self, username_queried, found_username):
        """
        Returns summary and data dictionaries for a successful username lookup.

        :param username_queried: str
        :param found_username: DataBreachUsernameSummary
        :return: tuple
        """
        summary = {
            'username_queried': username_queried,
            'username_was_found': True
        }
        data = {
            'username_retrieved': found_username.username,
            'username_was_found': True,
            'distinct_password_count': found_username.distinct_password_count,
            'breach_count': found_username.breach_count
        }
        return summary, data

    def _lookup_failure(self, username_queried):
        """
        Returns summary and data dictionaries for an unsuccessful username lookup.

        :param username_queried: str
        :return: tuple
        """
        summary = {
            'username_queried': username_queried,
            'username_was_found': False
        }
        data = {
            'username_retrieved': '',
            'username_was_found': False,
            'distinct_password_count': 0,
            'breach_count': 0
        }
        return summary, data
