# --
# File: berryio_connector.py
#
# Copyright (c) 2016-2021 Splunk Inc.
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# --

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# THIS Connector imports
from berryio_consts import *

import requests
import time
import simplejson as json


class BerryIOConnector(BaseConnector):

    # actions supported by this script
    ACTION_ID_SET_GPIO_MODE = "set_mode"
    ACTION_ID_SET_GPIO_VALUE = "set_value"
    ACTION_ID_GET_GPIO_STATUS = "get_status"
    ACTION_ID_TEST_ASSET_CONNECTIVITY = "test_asset_connectivity"

    def __init__(self):
        """ """

        self.__id_to_name = {}

        # Call the BaseConnectors init first
        super(BerryIOConnector, self).__init__()

    def initialize(self):
        """ Called once for every action, all member initializations occur here"""

        config = self.get_config()

        # get user and password for basic auth
        self._auth_username = config.get('username', '')
        self._auth_password = config.get('password', '')

        # Get the Base URL from the asset config and so some cleanup
        self._base_url = config.get('base_url', BERRYIO_BASE_URL)
        if self._base_url.endswith('/'):
            self._base_url = self._base_url[:-1]

        # The host member extacts the host from the URL, is used in creating status messages
        self._host = self._base_url[self._base_url.find('//') + 2:]

        # The headers, initialize them here once and use them for all other REST calls
        self._headers = {'Accept': 'application/json'}

        # The common part after the base url, but before the specific endpoint
        # Intiliazed here and used on every REST endpoint calls
        # self._api_uri = config.get('base_url', BERRYIO_BASE_API)
        self._api_uri = BERRYIO_BASE_API
        if self._api_uri.endswith('/'):
            self._api_uri = self._api_uri[:-1]
        self.save_progress('URI: {} - URL: {}'.format(self._api_uri, self._base_url))
        return phantom.APP_SUCCESS

    def _make_rest_call(self, endpoint, action_result, headers={}, params=None, data=None, method="get", retry=True):
        """ Function that makes the REST call to the device, generic function that can be called from various action handlers"""

        # Get the config
        config = self.get_config()

        # Create the headers
        headers.update(self._headers)

        if method in ['put', 'post']:
            headers.update({'Content-Type': 'application/json'})

        # get or post or put, whatever the caller asked us to use, if not specified the default will be 'get'
        request_func = getattr(requests, method)

        # handle the error in case the caller specified a non-existant method
        if not request_func:
            action_result.set_status(phantom.APP_ERROR, ERR_API_UNSUPPORTED_METHOD, method=method)

        # self.save_progress(USING_BASE_URL, base_url=self._base_url, api_uri=self._api_uri, endpoint=endpoint)
        # self.save_progress('Using {0} for authentication'.format(self._auth_method))
        # Make the call
        if retry:
            retry_count = MAX_TIMEOUT_DEF
        else:
            retry_count = 1
        success = False
        # self.debug_print('Test point 1')
        while not success and (retry_count > 0):
            #
            # self.debug_print('Entering while loop for rest')
            try:
                r = request_func(self._base_url + self._api_uri + endpoint,  # The complete url is made up of the base_url, the api url and the endpiont
                        # auth=(self._username, self._key),  # The authentication method, currently set to simple base authentication
                        data=json.dumps(data) if data else None,  # the data, converted to json string format if present, else just set to None
                        headers=headers,  # The headers to send in the HTTP call
                        verify=config[phantom.APP_JSON_VERIFY],  # should cert verification be carried out?
                        auth=(self._auth_username, self._auth_password),  # user and pass for basic auth
                        params=params)  # uri parameters if any
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, ERR_SERVER_CONNECTION, e), None

            # r.encoding='utf-8'

            # self.debug_print('REST url: {0} - attempt: {1}'.format(r.url, (MAX_TIMEOUT_DEF - retry_count)))
            self.debug_print('REST text: {0}'.format(r.text))
            if r.status_code == 200:
                success = True
            else:
                time.sleep(SLEEP_SECS)
                retry_count -= 1

        # Handle any special HTTP error codes here, many devices return an HTTP error code like 204. The requests module treats these as error,
        # so handle them here before anything else, uncomment the following lines in such cases
        # if (r.status_code >= 500): # these guys like 502/504 errors due to gateway failures, we can retry a few times.
        #    return (phantom.APP_SUCCESS, resp_json)
        # Process errors
        # self.debug_print('Response returned: {}'.format(r.text))
        if phantom.is_fail(r.status_code) or r.text is False or BERRYIO_FAIL_ERROR in r.text:
            self.debug_print('FAILURE: Found in the app response.\nResponse: {}'.format(r.text))
            # if response:
            #     action_result.set_summary({'error' : r.text})
            # self.debug_print(action_result.get_message())
            # action_result.set_summary({'error' : r.text})
            # self.set_status(phantom.APP_ERROR)
            return phantom.APP_ERROR, r

        if r.text:
            if BERRYIO_INPUT_INVALID.lower() in r.text.lower() or BERRYIO_NO_RESULTS.lower() in r.text.lower():
                self.debug_print('FAILURE: Found in the app response.\nResponse: {}'.format(r.text))
                # action_result.set_summary({'error' : r.text})
                return phantom.APP_SUCCESS, ('error: ' + r)
        #
        # Handle/process any errors that we get back from the device
        if r.status_code == 200:
            # Success
            return phantom.APP_SUCCESS, r

        # Failure
        # action_result.add_data({'raw':r.text})

        # details = json.dumps(resp_json).replace('{', '').replace('}', '')

        # return (action_result.set_status(phantom.APP_ERROR, ERR_FROM_SERVER.format(status=r.status_code, detail=details)), resp_json)
        return action_result.set_status(phantom.APP_ERROR, ERR_FROM_SERVER.format(status=r.status_code, detail=r.text)), r

    def _test_connectivity(self, param):
        """ Action handler for the '_test_connectivity' action"""

        # This is an action that needs to be represented by the ActionResult object
        # So create one and add it to 'self' (i.e. add it to the BaseConnector)
        # When the action_result is created this way, the parameter is also passed.
        # Other things like the summary, data and status is set later on.
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Endpoint
        endpoint = BERRYIO_VERSION

        # Progress
        self.save_progress(USING_BASE_URL.format(base_url=self._base_url, api_uri=self._api_uri, endpoint=endpoint))

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Make the rest call, note that if we try for cached and its not there, it will automatically go to start a new analysis.
        # unless specified start a new as above.
        ret_val, response = self._make_rest_call(endpoint, action_result, params='', retry=False)
        self.debug_print('Ret_val: {}'.format(ret_val))
        """
        OK: V1.15.0,2016-11-17
        """
        if ret_val:
            if 'ok' in response.text.lower():  # summary has been set to error per rest pull code, exit with success
                # Set the Status
                self.save_progress(response.text)
                self.save_progress(SUCC_CONNECTIVITY_TEST)
                return self.set_status(phantom.APP_SUCCESS)
            else:
                status_message = 'Connection failed. HTTP status_code: {}, reason:\n\n {}'.format(response.status_code, response.text)
                self.save_progress(status_message)
                self.save_progress(ERR_CONNECTIVITY_TEST)
                return self.set_status(phantom.APP_ERROR)
        status_message = 'Connection failed.'
        self.save_progress(ERR_CONNECTIVITY_TEST)
        self.save_progress(status_message)
        return self.set_status(phantom.APP_ERROR)

    def _get_gpio_status(self, param):
        """ Action handler for the '_get_gpio_status' action"""

        # This is an action that needs to be represented by the ActionResult object
        # So create one and add it to 'self' (i.e. add it to the BaseConnector)
        # When the action_result is created this way, the parameter is also passed.
        # Other things like the summary, data and status is set later on.
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Endpoint
        endpoint = BERRYIO_GPIO_STATUS

        # Progress
        self.save_progress(USING_BASE_URL.format(base_url=self._base_url, api_uri=self._api_uri, endpoint=endpoint))

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Make the rest call, note that if we try for cached and its not there, it will automatically go to start a new analysis.
        # unless specified start a new as above.
        ret_val, response = self._make_rest_call(endpoint, action_result, params='', retry=True)
        self.debug_print('Ret_val: {}'.format(ret_val))
        """
        OK: 2,not_exported,not_exported 3,not_exported,
        not_exported 4,not_exported,not_exported 5,
        not_exported,not_exported 6,not_exported,
        not_exported 7,not_exported,not_exported 8,
        not_exported,not_exported 9,not_exported,not_exported 10,
        not_exported,not_exported 11,not_exported,not_exported 12,
        not_exported,not_exported 13,not_exported,not_exported 14,
        not_exported,not_exported 15,not_exported,not_exported 17,
        not_exported,not_exported 18,not_exported,not_exported 19,
        not_exported,not_exported 20,out,1 21,in,0 22,not_exported,
        not_exported 23,out,1 24,not_exported,not_exported 25,not_exported,
        not_exported 26,not_exported,not_exported 27,not_exported,not_exported
        """
        if ret_val:
            if response.text.strip().lower().startswith('ok'):
                response_data = { 'raw': response.text }
                gpio = []
                for line in (response.text.strip().split('\n')):
                    if "," in line:
                        linesp = line.strip().split(',')
                        gpio.append({ 'pin': linesp[0], 'mode': linesp[1], 'value': linesp[2]})
                response_data['gpio'] = gpio
                # Set the summary and response data
                action_result.add_data(response_data)
                # action_result.set_summary({ 'total_hops': len(response_data)})

                # Set the Status
                return action_result.set_status(phantom.APP_SUCCESS)
            else:
                return phantom.APP_ERROR
        else:
            return phantom.APP_ERROR

    def _set_gpio_mode(self, param):
        """ Action handler for the '_set_gpio_mode' action"""

        # This is an action that needs to be represented by the ActionResult object
        # So create one and add it to 'self' (i.e. add it to the BaseConnector)
        # When the action_result is created this way, the parameter is also passed.
        # Other things like the summary, data and status is set later on.
        action_result = self.add_action_result(ActionResult(dict(param)))

        pin = str(param.get('pin', ''))

        # Endpoint
        if param.get('mode', None):
            endpoint = BERRYIO_SET_MODE + pin + '/' + param.get('mode', '')
        elif param.get('value', None) is not None:
            endpoint = BERRYIO_SET_VALUE + pin + '/' + str(param.get('value', ''))

        # Progress
        self.save_progress(USING_BASE_URL.format(base_url=self._base_url, api_uri=self._api_uri, endpoint=endpoint))

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Make the rest call, note that if we try for cached and its not there, it will automatically go to start a new analysis.
        # unless specified start a new as above.
        ret_val, response = self._make_rest_call(endpoint, action_result, params='', retry=True)
        self.debug_print('Ret_val: {}'.format(ret_val))
        """
        OK:
        """
        if ret_val:
            if response.text.strip().lower().startswith('ok'):
                response_data = { 'raw': response.text }
                # Set the summary and response data
                action_result.add_data(response_data)
                # action_result.set_summary({ 'total_hops': len(response_data)})

                # Set the Status
                return action_result.set_status(phantom.APP_SUCCESS)
            else:
                return phantom.APP_ERROR
        else:
            return phantom.APP_ERROR

    def handle_action(self, param):
        """Function that handles all the actions"""

        # Get the action that we are supposed to carry out, set it in the connection result object
        action = self.get_action_identifier()

        # Intialize it to success
        ret_val = phantom.APP_SUCCESS

        # self.debug_print('DEBUG Action: {}'.format(action))
        # Bunch if if..elif to process actions
        if action == self.ACTION_ID_SET_GPIO_MODE:
            ret_val = self._set_gpio_mode(param)
        elif action == self.ACTION_ID_SET_GPIO_VALUE:
            ret_val = self._set_gpio_mode(param)
        elif action == self.ACTION_ID_GET_GPIO_STATUS:
            ret_val = self._get_gpio_status(param)
        elif action == self.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            ret_val = self._test_connectivity(param)

        # self.debug_print('DEBUG: ret_val: {}'.format(ret_val))

        return ret_val


if __name__ == '__main__':
    """ Code that is executed when run in standalone debug mode
    for .e.g:
    python2.7 ./berryio.py /tmp/berryio.json
    """

    # Imports
    import sys
    import pudb

    # Breakpoint at runtime
    pudb.set_trace()

    # The first param is the input json file
    with open(sys.argv[1]) as f:

        # Load the input json file
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=' ' * 4))

        # Create the connector class object
        connector = BerryIOConnector()

        # Se the member vars
        connector.print_progress_message = True

        # Call BaseConnector::_handle_action(...) to kickoff action handling.
        ret_val = connector._handle_action(json.dumps(in_json), None)

        # Dump the return value
        print(ret_val)

    exit(0)
