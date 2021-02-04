# File: incident.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from datetime import datetime

from .ds_model import DSModel


class Incident(DSModel):

    def __init__(self, incident_id, payload):
        self._id = incident_id
        self._published = payload.get('published')
        self._modified = payload.get('modified')
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
        return 'Incident[id={}, published={}, payload={}]'.format(self.id, self.published, self.payload)

    @classmethod
    def from_json(cls, json):
        incident_id = DSModel.cast(json.get('id'), int)
        return cls(incident_id, json)
