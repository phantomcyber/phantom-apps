# File: sixgill_artifact.py
#
# Copyright (c) 2021 Cybersixgill Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

from sixgilldarkfeed_consts import *
from sixgill_utils import SixgillUtils

import requests
import json


class SixgillArtifact(object):
    def __init__(self, connector):
        """
        :param connector: CyberSixgillConnector
        """
        self._connector = connector
        config = connector.get_config()
        self._container_label = config["ingest"]["container_label"]

        self._headers = {"ph-auth-token": config[AUTH_TOKEN]}

    def prepare_artifact(self, container_id, container_severity, indicator, indicator_dict):
        """
        Create an artifact from Sixgill Darkfeed.

        :param container_id: int
        :param indicator: Indicators
        :param indicator_dict: indicator type and value
        :return: dict
        """
        artifact = dict()
        sixgill_utils = SixgillUtils(self._connector)
        artifact["container_id"] = container_id
        artifact["label"] = self._container_label
        artifact["severity"] = container_severity
        artifact["type"] = SIXGILL_DARKFEED
        if SIXGILL_INDICATOR_TYPE in indicator_dict:
            artifact["name"] = f"{indicator_dict.get(SIXGILL_INDICATOR_TYPE)} {POSTFIX_ARTIFACT}"
        if SIXGILL_FEED_VALID_FROM in indicator:
            artifact["start_time"] = indicator.get(SIXGILL_FEED_VALID_FROM)
        if SIXGILL_FEED_ID in indicator:
            artifact["source_data_identifier"] = sixgill_utils.sixgill_delimit_id(indicator.get(SIXGILL_FEED_ID))
        artifact["tags"] = sixgill_utils.get_labels(indicator)
        if SIXGILL_INDICATOR_TYPE in indicator_dict:
            indicator_type = indicator_dict.get(SIXGILL_INDICATOR_TYPE).replace("-", "")
            artifact["cef"] = {
                indicator_type: indicator_dict.get(SIXGILL_INDICATOR_VALUE),
                SIXGILL_ARTIFACT_ACTOR: indicator.get(SIXGILL_FEED_ACTOR),
                SIXGILL_ARTIFACT_CONFIDENCE: indicator.get(SIXGILL_FEED_CONFIDENCE),
                SIXGILL_ARTIFACT_FEEDID: indicator.get(SIXGILL_FEED_FEEDID),
                SIXGILL_ARTIFACT_FEEDNAME: indicator.get(SIXGILL_FEED_FEEDNAME),
                SIXGILL_ARTIFACT_POSTID: f"https://portal.cybersixgill.com/#/search?q=_id:{indicator.get(SIXGILL_FEED_POSTID)}",
                SIXGILL_ARTIFACT_POSTTITLE: indicator.get(SIXGILL_FEED_POSTTITLE),
                SIXGILL_ARTIFACT_SOURCE: indicator.get(SIXGILL_FEED_SOURCE),
            }
        artifact["cef"].update(sixgill_utils.get_mitre_vt_data(indicator))
        artifact["cef_types"] = dict()
        artifact["cef_types"][indicator_type] = [indicator_type.lower()]
        return [artifact]

    def update_artifact(self, artifact_id, artifact, verify_ssl):
        artifact = json.dumps(artifact[0], indent=4)
        query_url = f"{BASE_URL}{REST_ARTIFACT_API}{artifact_id}"
        update_artifact = requests.post(query_url, headers=self._headers, verify=verify_ssl, data=artifact)
        return update_artifact

    def delete_artifact(self, artifact_id, verify_ssl):
        query_url = f"{BASE_URL}{REST_ARTIFACT_API}{artifact_id}"
        delete_artifact = requests.delete(query_url, headers=self._headers, verify=verify_ssl)
        return delete_artifact
