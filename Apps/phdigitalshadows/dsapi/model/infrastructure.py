# File: infrastructure.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from .ds_model import DSModel


class Infrastructure(DSModel):

    def __init__(self, id, ip_address, port_number, transport, discovered_open,
                 incident_id, incident_scope, incident_type, incident_sub_type, incident_severity, incident_title):
        self._id = id
        self._ip_address = ip_address
        self._port_number = port_number
        self._transport = transport
        self._discovered_open = discovered_open
        self._incident_id = incident_id
        self._incident_scope = incident_scope
        self._incident_type = incident_type
        self._incident_sub_type = incident_sub_type
        self._incident_severity = incident_severity
        self._incident_title = incident_title

    @property
    def id(self):
        return self._id

    @property
    def ip_address(self):
        return self._ip_address

    @property
    def port_number(self):
        return self._port_number

    @property
    def transport(self):
        return self._transport

    @property
    def discovered_open(self):
        return self._discovered_open

    @property
    def incident_id(self):
        return self._incident_id

    @property
    def incident_scope(self):
        return self._incident_scope

    @property
    def incident_type(self):
        return self._incident_type

    @property
    def incident_sub_type(self):
        return self._incident_sub_type

    @property
    def incident_severity(self):
        return self._incident_severity

    @property
    def incident_title(self):
        return self._incident_title

    def __str__(self):
        return 'Infrastructure[id={}, ipaddress={}, port={}]'.format(self.id, self.ip_address, self.port_number)

    @classmethod
    def from_json(cls, json):
        cast = DSModel.cast
        return cls(cast(json.get('id'), int),
                   json.get('ipAddress'),
                   json.get('portNumber'),
                   json.get('transport'),
                   json.get('discoveredOpen'),
                   cast(json.get('incident').get('id'), int),
                   json.get('incident').get('scope'),
                   json.get('incident').get('type'),
                   json.get('incident').get('subType'),
                   json.get('incident').get('severity'),
                   json.get('incident').get('title'))
