# File: sixgill_reputation.py
#
# Copyright (c) 2021 Cybersixgill Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

from phantom.action_result import ActionResult

# Phantom App imports
import phantom.app as phantom

from sixgilldarkfeed_consts import *
from sixgill_utils import SixgillUtils

# Sixgill Libraries
from sixgill.sixgill_enrich_client import SixgillEnrichClient


class SixgillReputation(object):
    def __init__(self, connector):
        """
        :param connector: CyberSixgillConnector
        """
        self._connector = connector
        config = connector.get_config()

        self._sixgill_client_id = config[SIXGILL_API_ID_CFG]
        self._sixgill_api_secret_key = config[SIXGILL_API_SECRET_KEY_CFG]
        self._sixgill_phantom_channel_id = SIXGILL_CHANNEL_ID
        self._enrich_client = self._enrich_indicator_object()

    def _enrich_indicator_object(self):
        return SixgillEnrichClient(
            self._sixgill_client_id, self._sixgill_api_secret_key, self._sixgill_phantom_channel_id
        )

    def _get_enrich_data(self, enrich_indicators, action_result):
        """This method adds the result to the action result

        Arguments:
            enrich_indicators - received IOC's matching with the indicator
            action_result - action result object

        Returns:
            action_result status -- Returns the 'action_result' status
        """
        sixgill_utils = SixgillUtils(self._connector)
        action_result.update_summary({"No.of Indicator Found": len(enrich_indicators)})
        for indicator in enrich_indicators:
            action_result.add_data(sixgill_utils.create_repuation_dict(indicator))
        action_result.set_status(phantom.APP_SUCCESS, "Sixgill Darkfeed enrichment data...")
        action_result.append_to_message(f"No.of Indicator Found: {len(enrich_indicators)}")

    def _enrich(self, indicator_type, indicator_value, action_result):
        try:
            enrich_indicators = self._enrich_client.enrich_ioc(indicator_type, indicator_value)
            self._get_enrich_data(enrich_indicators, action_result)
            return action_result.get_status()
        except Exception as e:
            err = self._connector._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, err)

    def ip_reputation(self, param):
        """This method Query the Sixgill Darkfeed for a specific IP and receive all IOCs matching that IP.

        Arguments:
            param - paramter of the SixgillDarkfeed configuration

        Returns:
            action_result status -- Returns the 'action_result' status
        """
        action_result = ActionResult(dict(param))

        self._connector.debug_print(param)
        self._connector.add_action_result(action_result)
        self._ip = param[SIXGILL_IP]

        return self._enrich(SIXGILL_IP, self._ip, action_result)

    def url_reputation(self, param):
        """This method Query the Sixgill Darkfeed for a specific URL and receive all IOCs matching that URL.

        Arguments:
            param - paramter of the SixgillDarkfeed configuration

        Returns:
            action_result status -- Returns the 'action_result' status
        """
        action_result = ActionResult(dict(param))

        self._connector.debug_print(param)
        self._connector.add_action_result(action_result)
        self._url = param[SIXGILL_URL]

        return self._enrich(SIXGILL_URL, self._url, action_result)

    def hash_reputation(self, param):
        """This method Query the Sixgill Darkfeed for a specific hash and receive all IOCs matching that hash.

        Arguments:
            param - paramter of the SixgillDarkfeed configuration

        Returns:
            action_result status -- Returns the 'action_result' status
        """
        action_result = ActionResult(dict(param))

        self._connector.debug_print(param)
        self._connector.add_action_result(action_result)
        self._hash = param[SIXGILL_HASH]

        return self._enrich(SIXGILL_HASH, self._hash, action_result)

    def domain_reputation(self, param):
        """This method Query the Sixgill Darkfeed for a specific domain and receive all IOCs matching that domain.

        Arguments:
            param - paramter of the SixgillDarkfeed configuration

        Returns:
            action_result status -- Returns the 'action_result' status
        """
        action_result = ActionResult(dict(param))

        self._connector.debug_print(param)
        self._connector.add_action_result(action_result)
        self._domain = param[SIXGILL_DOMAIN]

        return self._enrich(SIXGILL_DOMAIN, self._domain, action_result)

    def postid_reputation(self, param):
        """This method Query the Sixgill Darkfeed for a specific Sixgill post ID
        (i.e. unique identifier of a specific post shared in the underground) and receive all IOCs shared in that post.

        Arguments:
            param - paramter of the SixgillDarkfeed configuration

        Returns:
            action_result status -- Returns the 'action_result' status
        """
        action_result = ActionResult(dict(param))

        self._connector.debug_print(param)
        self._connector.add_action_result(action_result)
        self._postid_value = param[SIXGILL_POSTID]

        try:
            enrich_indicators = self._enrich_client.enrich_postid(self._postid_value)
            self._get_enrich_data(enrich_indicators, action_result)
            return action_result.get_status()
        except Exception as e:
            err = self._connector._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, err)

    def actor_reputation(self, param):
        """This method Query the Sixgill Darkfeed and receive all IOCs shared by that threat actor

        Arguments:
            param - paramter of the SixgillDarkfeed configuration

        Returns:
            action_result status -- Returns the 'action_result' status
        """
        action_result = ActionResult(dict(param))

        self._connector.debug_print(param)
        self._connector.add_action_result(action_result)
        self._actor_value = param[SIXGILL_ACTOR]

        try:
            enrich_indicators = self._enrich_client.enrich_actor(self._actor_value)
            self._get_enrich_data(enrich_indicators, action_result)
            return action_result.get_status()
        except Exception as e:
            err = self._connector._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, err)
