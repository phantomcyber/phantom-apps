# File: certs.py
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
"""Utilities for certificate management."""

import os

certifi_available = False
certifi_where = None
try:
    from certifi import where as certifi_where
    certifi_available = True
except ImportError:
    pass

custom_ca_locater_available = False
custom_ca_locater_where = None
try:
    from ca_certs_locater import get as custom_ca_locater_where
    custom_ca_locater_available = True
except ImportError:
    pass


BUILTIN_CA_CERTS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "cacerts.txt"
)


def where():
    env = os.environ.get("HTTPLIB2_CA_CERTS")
    if env is not None:
        if os.path.isfile(env):
            return env
        else:
            raise RuntimeError("Environment variable HTTPLIB2_CA_CERTS not a valid file")
    if custom_ca_locater_available:
        return custom_ca_locater_where()
    if certifi_available:
        return certifi_where()
    return BUILTIN_CA_CERTS


if __name__ == "__main__":
    print(where())
