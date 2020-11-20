#
# Copyright (c) 2017 Digital Shadows Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from ds_model import DSModel


class DataBreachRecord(DSModel):

    def __init__(self, record_id, username, password, review, published, prior_username_breach_count,
                 prior_username_password_breach_count, prior_row_text_breach_count, payload):
        self._id = record_id
        self._username = username
        self._password = password
        self._review = review
        self._published = published
        self._prior_username_breach_count = prior_username_breach_count
        self._prior_username_password_breach_count = prior_username_password_breach_count
        self._prior_row_text_breach_count = prior_row_text_breach_count
        self._payload = payload

    @property
    def id(self):
        return self._id

    @property
    def username(self):
        return self._username

    @property
    def password(self):
        return self._password

    @property
    def review(self):
        return self._review

    @property
    def published(self):
        return self._published

    @property
    def prior_username_breach_count(self):
        return self._prior_username_breach_count

    @property
    def prior_username_password_breach_count(self):
        return self._prior_username_password_breach_count

    @property
    def prior_row_text_breach_count(self):
        return self._prior_row_text_breach_count

    @property
    def payload(self):
        return self._payload

    def __str__(self):
        return 'DataBreachRecord[id={}, username={}, payload={}]'.format(self.id, self.username, self.payload)

    @classmethod
    def from_json(cls, json):
        cast = DSModel.cast
        return cls(cast(json.get('id'), long),
                   json.get('username'),
                   json.get('password'),
                   json.get('review'),
                   json.get('published'),
                   cast(json.get('priorUsernameBreachCount'), int),
                   cast(json.get('priorUsernamePasswordBreachCount'), int),
                   cast(json.get('priorRowTextBreachCount'), int),
                   json)
