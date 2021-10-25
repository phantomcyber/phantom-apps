# File: forescoutcounteract_consts.py
#
# Copyright (c) 2018-2021 Splunk Inc.
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
#
#
# Define your constants here
FS_DEX_HOST_ENDPOINT = '/fsapi/niCore/Hosts'
FS_DEX_LIST_ENDPOINT = '/fsapi/niCore/Lists'

FS_DEX_TEST_CONNECTIVITY = \
    """<?xml version="1.0" encoding="UTF-8"?>
        <FSAPI TYPE="request" API_VERSION="1.0">
        <TRANSACTION TYPE="update">
        <OPTIONS CREATE_NEW_HOST="true"/>
        <HOST_KEY NAME="ip" VALUE="{host_key_value}"/>
            <PROPERTIES></PROPERTIES>
        </TRANSACTION>
        </FSAPI>"""

FS_DEX_UPDATE_SIMPLE_PROPERTY = \
    """<?xml version='1.0' encoding='utf-8'?>
        <FSAPI TYPE="request" API_VERSION="1.0">
        <TRANSACTION TYPE="update">
            <OPTIONS CREATE_NEW_HOST="{create_host}"/>
            <HOST_KEY NAME="{host_key_name}" VALUE="{host_key_value}"/>
                    <PROPERTIES>
                        <PROPERTY NAME="{property_name}">
                                <VALUE>{property_value}</VALUE>
                        </PROPERTY>
                    </PROPERTIES>
        </TRANSACTION>
        </FSAPI>"""

FS_DEX_DELETE_SIMPLE_PROPERTY = \
    """<?xml version='1.0' encoding='utf-8'?>
        <FSAPI TYPE="request" API_VERSION="1.0">
        <TRANSACTION TYPE="delete">
            <HOST_KEY NAME="{host_key_name}" VALUE="{host_key_value}"/>
                    <PROPERTIES>
                        <PROPERTY NAME="{property_name}" />
                    </PROPERTIES>
        </TRANSACTION>
        </FSAPI>"""

FS_DEX_UPDATE_LIST_PROPERTY = \
    """<?xml version="1.0" encoding="UTF-8"?>
        <FSAPI TYPE="request" API_VERSION="2.0">
        <TRANSACTION TYPE="{transaction_type}">
            <LISTS>
                {list_body}
            </LISTS>
        </TRANSACTION>
        </FSAPI>"""

FS_WEB_LOGIN = '/api/login'
FS_WEB_HOSTS = '/api/hosts'
FS_WEB_HOSTFIELDS = '/api/hostfields'
FS_WEB_POLICIES = '/api/policies'

# Error message constants
FS_ERR_CODE_MSG = "Error code unavailable"
FS_ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
FS_PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"

# validate integer
ERR_VALID_INT_MSG = "Please provide a valid integer value in the {}"
ERR_NON_NEG_INT_MSG = "Please provide a valid non-negative integer value in the {}"
ERR_POSITIVE_INTEGER_MSG = "Please provide a valid non-zero positive integer value in the {}"
HOST_ID_INT_PARAM = "'host_id' action parameter"
