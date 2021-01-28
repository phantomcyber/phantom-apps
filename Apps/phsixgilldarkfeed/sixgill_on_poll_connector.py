# File: sixgill_on_poll_connector.py
#
# Copyright (c) 2021 Cybersixgill Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

import phantom.app as phantom
from phantom.action_result import ActionResult

from sixgilldarkfeed_consts import *
from sixgill_container import SixgillContainer
from sixgill_artifact import SixgillArtifact
from sixgill_utils import SixgillUtils

# Sixgill Libraries
from sixgill.sixgill_constants import FeedStream
from sixgill.sixgill_feed_client import SixgillFeedClient
import sixgill.sixgill_utils

import re


class SixgillOnPollConnector(object):
    def __init__(self, connector):
        """
        :param connector: CyberSixgillConnector
        """
        self._connector = connector
        config = connector.get_config()

        # Reading the user configured values
        self._sixgill_client_id = config[SIXGILL_API_ID_CFG]
        self._sixgill_api_secret_key = config[SIXGILL_API_SECRET_KEY_CFG]
        self._verify_ssl = config[SIXGILL_VERIFY_SSL]
        self._container_label = config["ingest"]["container_label"]

        # Passing the channel ID from the const
        self._sixgill_phantom_channel_id = SIXGILL_CHANNEL_ID

        # Setting the default Sixgill Darkfeed intelligence ingestion to 2000
        # Change this value if you need to ingest more indicators in a single poll
        self._limit = 2000

    def _sixgill_get_sixgill_pattern_type(self, indicator):
        """This method parses the 'Pattern' of the darkfeed to retrieve the IOC's

        Arguments:
            indicator - Sixgill Darkfeed Indicator

        Returns:
            list -- Key, Value pair of the retrived IOC's
        """
        stix_regex_parser = re.compile(r"([\w-]+?):(\w.+?) (?:[!><]?=|IN|MATCHES|LIKE) '(.*?)' *[OR|AND|FOLLOWEDBY]?")
        indicator_list = []
        if "pattern" in indicator:
            for indicator_type, sub_type, value in stix_regex_parser.findall(indicator.get("pattern")):
                indicator_dict = {}
                if indicator_type == "file":
                    if "MD5" in sub_type:
                        indicator_dict.update({"Type": "MD5", "Value": value})
                    if "SHA-1" in sub_type:
                        indicator_dict.update({"Type": "SHA-1", "Value": value})
                    if "SHA-256" in sub_type:
                        indicator_dict.update({"Type": "SHA-256", "Value": value})
                    indicator_list.append(indicator_dict)
                elif indicator_type == "url":
                    indicator_dict.update({"Type": "URL", "Value": value})
                    indicator_list.append(indicator_dict)
                elif indicator_type == "ipv4-addr":
                    indicator_dict.update({"Type": "IP Address", "Value": value})
                    indicator_list.append(indicator_dict)
                elif indicator_type == "domain":
                    indicator_dict.update({"Type": "DOMAIN", "Value": value})
                    indicator_list.append(indicator_dict)
        return indicator_list

    def on_poll(self, param):
        """This method ingest/update/delete the Sixgill Darkfeed Intelligence

        Arguments:
            param - paramter of the SixgillDarkfeed configuration

        Returns:
            action_result status -- Returns the 'action_result' status
        """
        self._connector.debug_print(param)

        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)

        # Setting up the limit to the SixgillFeedClient which defaults to 2000
        if CONTAINER_COUNT in param and param.get(CONTAINER_COUNT) < 2000:
            self._limit = param.get(CONTAINER_COUNT)
        try:
            darkfeed_client = SixgillFeedClient(
                self._sixgill_client_id,
                self._sixgill_api_secret_key,
                self._sixgill_phantom_channel_id,
                FeedStream.DARKFEED,
                bulk_size=self._limit,
            )
            indicator_object = darkfeed_client.get_bundle().get("objects")
            sixgill_container = SixgillContainer(self._connector)
            sixgill_artifact = SixgillArtifact(self._connector)
            sixgill_utils = SixgillUtils(self._connector)
            self._connector.save_progress("Ingesting Sixgill Darkfeed Intelligence ...")
            failuer_indicator_list = []
            if len(indicator_object) > 2:
                for indicator in indicator_object:
                    if sixgill.sixgill_utils.is_indicator(indicator):
                        self._indicator_id = sixgill_utils.sixgill_delimit_id(indicator.get(SIXGILL_FEED_ID))
                        indicator_list = self._sixgill_get_sixgill_pattern_type(indicator)
                        container = sixgill_container.prepare_container(indicator)

                        # Search the phantom if the indicator from API does exist in the phantom SOAR platform
                        # Retry search functionality for 5 times in case of a network issue
                        for count in range(int(TRY_AGAIN)):
                            feed_dict = sixgill_utils.search_feed(self._indicator_id)
                            if len(feed_dict) > 0:
                                break

                        if feed_dict:
                            # If the indicator includes a "revoked" = true flag, the indicator will get deleted from the phantom SOAR platform
                            sixgill_utils.delete_event(
                                feed_dict, indicator, sixgill_container, sixgill_artifact, self._verify_ssl
                            )
                            # Update the event and the artifact if the source ID of the indicator exists in phantom SOAR platform
                            sixgill_utils.update_event(
                                feed_dict,
                                indicator_list,
                                indicator,
                                container,
                                sixgill_container,
                                sixgill_artifact,
                                self._verify_ssl,
                            )
                            action_result.set_status(phantom.APP_SUCCESS)
                        else:
                            # Ingest the indicator in to the phantom if the indicator does not exist in the phantom SOAR platform
                            container_status, container_message, container_id = self._connector.save_container(container)
                            if container_status == phantom.APP_SUCCESS:
                                for indicator_dict in indicator_list:
                                    artifacts = sixgill_artifact.prepare_artifact(
                                        container_id, container["severity"], indicator, indicator_dict
                                    )
                                    artifact_status, artifact_message, artifact_id_list = self._connector.save_artifacts(
                                        artifacts
                                    )
                                action_result.set_status(phantom.APP_SUCCESS)
                            else:
                                # Return error status if the indicator didn't get ingested
                                action_result.set_status(phantom.APP_ERROR)
            else:
                self._connector.save_progress("There is no new Threat Intelligence available")
                action_result.set_status(phantom.APP_SUCCESS)
            self._connector.debug_print(f"Indicators Failed to ingest log: {failuer_indicator_list}")
            self._connector.save_progress("Sixgill Darkfeed Intelligence ingested")

            # Indicators which got ingested into the Phantom SOAR platform will get commited to the Sixgill Darkfeed API end point
            darkfeed_client.commit_indicators()
            return action_result.get_status()
        except Exception as e:
            err = self._connector._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, err)
