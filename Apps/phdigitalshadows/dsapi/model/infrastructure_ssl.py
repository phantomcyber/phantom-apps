# File: infrastructure_ssl.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from .ds_model import DSModel


class InfrastructureSSL(DSModel):

    def __init__(self, id, payload):
        self._id = id
        self._payload = payload

    @property
    def id(self):
        return self._id

    @property
    def payload(self):
        return self._payload

    def __str__(self):
        return 'InfrastructureSSL[id={}, payload={}]'.format(self.id, self.payload)

    @classmethod
    def from_json(cls, json):
        cast = DSModel.cast
        return cls(cast(json.get('id'), int), json)
