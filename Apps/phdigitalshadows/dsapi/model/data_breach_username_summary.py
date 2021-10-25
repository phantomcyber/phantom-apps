# File: data_breach_username_summary.py
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
