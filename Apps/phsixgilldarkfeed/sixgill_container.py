# File: sixgill_container.py
#
# Copyright (c) 2021 Cybersixgill Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
from sixgilldarkfeed_consts import *
from sixgill_utils import SixgillUtils

import requests
import json


class SixgillContainer(object):
    def __init__(self, connector):
        """
        :param connector: CyberSixgillConnector
        """
        self._connector = connector
        config = connector.get_config()

        self._container_label = config["ingest"]["container_label"]
        self._headers = {"ph-auth-token": config[AUTH_TOKEN]}
        # self._headers = {"ph-auth-token": AUTH_TOKEN}

    def prepare_container(self, indicator):
        """
        Create a container from Cybersixgill Indicators.

        :param indicator: Indicators
        :return: dict
        """
        phantom_serverity_transform = SixgillUtils(self._connector)
        container = dict()
        container["label"] = self._container_label
        container["name"] = f'Sixgill Darkfeed - {indicator.get("description")}'
        if "sixgill_severity" in indicator:
            severity, sensitivity = phantom_serverity_transform.ds_to_phantom_severity_transform(
                indicator.get("sixgill_severity")
            )
            container["severity"] = severity
            container["sensitivity"] = sensitivity
        else:
            container["severity"] = DEFAULT_SEVERITY
            container["sensitivity"] = DEFAULT_SENSITIVITY
        container["status"] = SIXGILL_INDICATOR_STATUS
        container["event_type"] = PHANTOM_EVENT_TYPE
        container["ingest_app_id"] = self._connector.get_app_id()
        return container

    def update_container(self, container_id, container, verify_ssl):
        container = json.dumps(container, indent=4)
        query_url = f"{self._connector._get_phantom_base_url()}{REST_CONTAINER_API}{container_id}"
        update_event = requests.post(query_url, headers=self._headers, verify=verify_ssl, data=container)
        return update_event

    def delete_container(self, container_id, verify_ssl):
        query_url = f"{self._connector._get_phantom_base_url()}{REST_CONTAINER_API}{container_id}"
        delete_event = requests.delete(query_url, headers=self._headers, verify=verify_ssl)
        return delete_event
