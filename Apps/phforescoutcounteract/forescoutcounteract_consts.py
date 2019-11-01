# --
# File: forescoutcounteract_consts.py
# Copyright (c) 2018 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
#
# --

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
