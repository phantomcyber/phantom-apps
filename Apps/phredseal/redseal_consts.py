# File: redseal_consts.py
# Copyright (c) 2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

REDSEAL_CONFIG_SERVER_URL = 'server_url'
REDSEAL_CONFIG_VERIFY_SERVER_CERT = 'verify_server_cert'
REDSEAL_CONFIG_USERNAME = 'username'
REDSEAL_CONFIG_PASSWORD = 'password'
REDSEAL_DATA_ENDPOINT = '/data'
REDSEAL_DEVICE_ENDPOINT = '/group/Primary+Capability'
REDSEAL_SUBNET_ENDPOINT = '/group/Subnets'
REDSEAL_POLICY_ENDPOINT = '/policy'
REDSEAL_ZONE_QUERY_ENDPOINT = '/policy/{policy_name}/access_details'
REDSEAL_TYPE = 'type'
REDSEAL_QUERY_IMPACT_ENDPOINT = '/impact'
REDSEAL_QUERY_ACCESS_ENDPOINT = '/access'
REDSEAL_QUERY_THREATS_ENDPOINT = '/threats'
REDSEAL_SOURCE_ID = 'source'
REDSEAL_DESTINATION_ID = 'destination'
REDSEAL_SOURCE_TYPE = 'source_type'
REDSEAL_DESTINATION_TYPE = 'destination_type'
REDSEAL_QUERY_TYPE_IMPACT = 'WHAT_IF'
REDSEAL_QUERY_TYPE_ACCESS = 'NETMAP'
REDSEAL_QUERY_TYPE_THREATS = 'THREATMAP'
REDSEAL_SUBMIT_PUT_ERROR = 'Submit a Query via PUT'
REDSEAL_INVALID_URL_ERROR = 'Data from server: Invalid Server URL'
REDSEAL_NO_ID_MESSAGE = 'Invalid or missing Source/Destination parameter for given type'
REDSEAL_CONTAINER_ERROR = 'Error while creating container'
REDSEAL_ARTIFACT_ERROR = 'Error while creating artifact'
REDSEAL_TEST_CONNECTION = 'Querying endpoint to verify the credentials provided'
REDSEAL_TEST_CONNECTIVITY_FAILED = 'Test Connectivity Failed'
REDSEAL_TEST_CONNECTIVITY_PASSED = 'Test Connectivity Passed'
REDSEAL_TEST_CONNECTIVITY_TIMEOUT = 30
REDSEAL_PUT_REQUEST_DATA_BODY = """
            <Query>
                <Protocol>any</Protocol>
                <Name>Phantom_Query</Name>
                <Sources>
                    <Targets>
                        <Target>
                            <ID>{source}</ID>
                            <Type>{source_type}</Type>
                        </Target>
                    </Targets>
                    <Ports>any</Ports>
                    <IPs>any</IPs>
                    <Restrict>NONE</Restrict>
                </Sources>
                <Destinations>
                    <Targets>
                        <Target>
                            <ID>{destination}</ID>
                            <Type>{destination_type}</Type>
                        </Target>
                    </Targets>
                    <Ports>any</Ports>
                    <IPs>any</IPs>
                    <Restrict>NONE</Restrict>
                </Destinations>
                <Type>{query_type}</Type>
                <Track>false</Track>
            </Query>

        """
