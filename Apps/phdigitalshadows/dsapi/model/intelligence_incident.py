# File: intelligence_incident.py
#
# Copyright (c) 2020-2021 Digital Shadows Ltd.
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
from datetime import datetime

from .ds_model import DSModel


class IntelligenceIncident(DSModel):

    def __init__(self, incident_id, payload):
        self._id = incident_id
        self._published = payload.get('published')
        self._modified = payload.get('	')
        self._payload = payload

    @property
    def id(self):
        return self._id

    @property
    def published(self):
        return self._published

    @property
    def modified(self):
        return self._modified

    @property
    def payload(self):
        return self._payload

    def published_as_datetime(self):
        """
        Parses published datetime string.
        Date Format example: 2014-06-23T13:30:51.156Z

        :return: datetime
        """
        return datetime.strptime(self.published, '%Y-%m-%dT%H:%M:%S.%fZ')

    def __str__(self):
        return 'IntelligenceIncident[id={}, published={}, payload={}]'.format(self.id, self.published, self.payload)

    @classmethod
    def from_json(cls, json):
        incident_id = DSModel.cast(json.get('id'), int)
        return cls(incident_id, json)

