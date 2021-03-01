# File: intelligence_incident_ioc.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from datetime import datetime

from .ds_model import DSModel


class IntelligenceIncidentIoc(DSModel):

    def __init__(self, payload):
        self._payload = payload

    @property
    def payload(self):
        return self._payload

    def __str__(self):
        return 'IntelligenceIncidentIoc[payload={}]'.format(self.payload)

    @classmethod
    def from_json(cls, json):
        return cls(json)
