# File: data_breach.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from .ds_model import DSModel


class DataBreach(DSModel):

    def __init__(self, breach_id, title, domain_name, occurred, modified, published,
                 incident_id, incident_scope, incident_type, incident_severity, incident_title,
                 domain_count, record_count, source_url, organisation_username_count, payload):
        self._id = breach_id
        self._title = title
        self._domain_name = domain_name
        self._occurred = occurred
        self._modified = modified
        self._published = published
        self._incident_id = incident_id
        self._incident_scope = incident_scope
        self._incident_type = incident_type
        self._incident_severity = incident_severity
        self._incident_title = incident_title
        self._domain_count = domain_count
        self._record_count = record_count
        self._source_url = source_url
        self._organisation_username_count = organisation_username_count
        self._payload = payload

    @property
    def id(self):
        return self._id

    @property
    def title(self):
        return self._title

    @property
    def domain_name(self):
        return self._domain_name

    @property
    def occurred(self):
        return self._occurred

    @property
    def modified(self):
        return self._modified

    @property
    def published(self):
        return self._published

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
    def incident_severity(self):
        return self._incident_severity

    @property
    def incident_title(self):
        return self._incident_title

    @property
    def domain_count(self):
        return self._domain_count

    @property
    def record_count(self):
        return self._record_count

    @property
    def source_url(self):
        return self._source_url

    @property
    def organisation_username_count(self):
        return self._organisation_username_count

    @property
    def payload(self):
        return self._payload

    def __str__(self):
        return 'Username[id={}, domain={}, payload={}]'.format(self.id, self.domain_name, self.payload)

    @classmethod
    def from_json(cls, json):
        cast = DSModel.cast
        return cls(cast(json.get('id'), int),
                   json.get('title'),
                   json.get('domainName'),
                   json.get('occurred'),
                   json.get('modified'),
                   json.get('published'),
                   cast(json.get('incident').get('id'), int),
                   json.get('incident').get('scope'),
                   json.get('incident').get('type'),
                   json.get('incident').get('severity'),
                   json.get('incident').get('title'),
                   cast(json.get('domainCount'), int),
                   cast(json.get('recordCount'), int),
                   json.get('sourceUrl'),
                   cast(json.get('organisationUsernameCount'), int), json)
