#
# Copyright (c) 2017 Digital Shadows Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from ds_model import DSModel


class SearchEntities(DSModel):

    def __init__(self, payload):
        self._payload = payload

    @property
    def payload(self):
        return self._payload

    def __str__(self):
        return 'SearchEntity[payload={}]'.format(self.payload)

    @classmethod
    def from_json(cls, json):
        cast = DSModel.cast
        return cls(json)
