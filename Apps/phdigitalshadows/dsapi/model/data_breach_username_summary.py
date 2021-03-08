# File: data_breach_username_summary.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from .ds_model import DSModel


class DataBreachUsernameSummary(DSModel):

    def __init__(self, username, distinct_password_count, breach_count, payload):
        self._username = username
        self._distinct_password_count = distinct_password_count
        self._breach_count = breach_count
        self._payload = payload

    @property
    def username(self):
        return self._username

    @property
    def distinct_password_count(self):
        return self._distinct_password_count

    @property
    def breach_count(self):
        return self._breach_count

    @property
    def payload(self):
        return self._payload

    def __str__(self):
        return 'UsernameSummary[username={}, distinct_password_count={}, breach_count={}, payload={}]'\
            .format(self._username, self._distinct_password_count, self._breach_count, self.payload)

    @classmethod
    def from_json(cls, json):
        cast = DSModel.cast
        return cls(json.get('username'),
                   cast(json.get('distinctPasswordCount'), int),
                   cast(json.get('breachCount'), int),
                   json)
