# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from akamainetworklists_consts import *
import requests
import json
from bs4 import BeautifulSoup
# Import Akamai Edgegrid authentication module
from akamai.edgegrid import EdgeGridAuth
# import pudb


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class AkamaiNetworkListsConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(AkamaiNetworkListsConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._client_token = None
        self._client_secret = None
        self._access_token = None

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace(u'{', '{{').replace(u'}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + AKAMAI_API_PATH + endpoint

        try:
            r = requests.Session()
            r.auth = EdgeGridAuth(
                client_token=self._client_token,
                client_secret=self._client_secret,
                access_token=self._access_token
            )
            print(vars(r))
            r = request_func(url, auth=r.auth, **kwargs)

        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        """ This function is used test connectivity to Akamai
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")

        # make rest call
        ret_val, response = self._make_rest_call(AKAMAI_NETWORK_LIST_ENDPOINT, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_list_networks(self, param):
        """ This function is used list out all the networks lists details. We can also search by name to get a specific network list.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        if param.get("includeelements"):
            params['includeelements'] = param.get("includeelements")
        if param.get("extended"):
            params['extended'] = param.get("extended")
        if param.get("search"):
            params['search'] = param.get("search")

        endpoint = self._process_parameters(AKAMAI_NETWORK_LIST_ENDPOINT, params)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_network(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        if param.get("includeelements"):
            params['includeelements'] = param.get("includeelements")
        if param.get("extended"):
            params['extended'] = param.get("extended")
        if param.get('networklistid'):
            param_networklistid = param.get('networklistid').split(",")

        # Loop through each Network ID to retrive the data.
        for networklist in param_networklistid:
            # Format the URI
            endpoint = self._process_parameters(AKAMAI_NETWORK_LIST_ENDPOINT + "/{}".format(networklist), params)

            # make rest call
            ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

            if (phantom.is_fail(ret_val)):
                # the call to the 3rd party device or service failed, action result should contain all the error details
                # for now the return is commented out, but after implementation, return from here
                return action_result.get_status()

            # Now post process the data,  uncomment code as you deem fit
            # Add the response into the data section
            action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_element(self, param):
        # Use  POST /network-list/v2/network-lists/{networkListId}/append since you can add more than one element to a list.
        # Should be easier than using the 'Add an element' function which you can only add one at a time.

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        param_elements = param.get('elements').split(",")

        if len(param_elements) <= 1:
            # Create the param data to build the URI correctly. Only doing this to reuse code.
            # Can assign manually but it wont be as flexiable if the API changes.
            params = {'element': param.get('elements')}

            endpoint = self._process_parameters("{}/{}/elements".format(AKAMAI_NETWORK_LIST_ENDPOINT, param.get('networklistid')), params)

            # make rest call
            ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None, method="put")
        else:
            data = {"list": []}
            # Rebuild the elements as JSON
            for element in param_elements:
                # Add element to the list
                data['list'].append(element)

            endpoint = "{}/{}/append".format(AKAMAI_NETWORK_LIST_ENDPOINT, param.get('networklistid'))

            # make rest call
            ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None, method="post", json=data)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_remove_element(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        param_elements = param.get('elements').split(",")

        if len(param_elements) < 2:
            # Create the param data to build the URI correctly. Only doing this to reuse code.
            # Can assign manually but it wont be as flexiable if the API changes.
            params = {'element': param.get('elements')}

            endpoint = self._process_parameters("{}/{}/elements".format(AKAMAI_NETWORK_LIST_ENDPOINT, param.get('networklistid')), params)

            # make rest call
            ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None, method="delete")
        else:
            # This is a hack to remove multiple elements at a time. I use the "Update a network list" API to be able to remove multiple IP's / CIDR's.

            # Need to get the list of items before we can remove them. We also need other data to be able to update the network list.
            # Format the URI
            endpoint = "{}/{}".format(AKAMAI_NETWORK_LIST_ENDPOINT, param.get('networklistid'))

            # make rest call
            ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

            networkList = response['list']

            # Loop through the parameters passed.
            for item in param_elements:
                # Index is used to pop the item from the list
                index = 0
                # Loop through the current list of addresses
                for list in networkList:
                    if item == list:
                        networkList.pop(index)
                    index += 1

            # Create the data we are going to update the list details with. 
            # All fields here are required for the "Update a network list" API
            data = {
                "name": response.get('name', ''),
                "description": response.get('description', ''),
                "type": response.get('type', ''),
                "syncPoint": response.get('syncPoint', ''),
                "list": networkList
            }

            # make rest call
            ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None, method="put", json=data)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_network(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        ip_data = []

        ip_list = param.get('list').split(",")

        for ip in ip_list:
            ip_data.append(ip)

        data = {
            "name": param.get('name'),
            "type": param.get('type'),
            "description": param.get('description'),
            "list": ip_data
        }

        endpoint = "{}".format(AKAMAI_NETWORK_LIST_ENDPOINT)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None, method="post", json=data)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_network(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        endpoint = "{}/{}/details".format(AKAMAI_NETWORK_LIST_ENDPOINT, param.get('networklistid'))

        data = {
            "name": param.get('name'),
            "description": param.get('description')
        }

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None, method="put", json=data)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_network(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        endpoint = "{}/{}".format(AKAMAI_NETWORK_LIST_ENDPOINT, param.get('networklistid'))

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None, method="delete")

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_activate_network(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        data = {
            "comments": param.get('comments', '')
        }

        # Notification parameter is used 
        if param.get("notification"):
            notificationEmails = []

            for notificationEmail in param.get("notification").split(',')
                notificationEmails.append(notificationEmail)

            data['notification'] = notificationEmails

        endpoint = "{}/{}/environments/{}/activate".format(AKAMAI_NETWORK_LIST_ENDPOINT, param.get('networklistid'), param.get('environment'))

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None, method="post", json=data)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_activation_status(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = "{}/{}/environments/{}/status".format(AKAMAI_NETWORK_LIST_ENDPOINT, param.get('networklistid'), param.get('environment'))

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_activation_snapshot(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {'extended': param.get('extended')}

        endpoint = self._process_parameters("{}/{}/sync-points/{}/history".format(AKAMAI_NETWORK_LIST_ENDPOINT,
                                                                            param.get('networklistid'), param.get('syncpoint')), params)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_activation_details(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = "{}/{}".format(AKAMAI_ACTIVATIONS_ENDPOINT, param.get('activationid'))

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.
        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """
        self.debug_print('action_id', self.get_action_identifier())

        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'list_networks': self._handle_list_networks,
            'get_network': self._handle_get_network,
            'create_network': self._handle_create_network,
            'update_network': self._handle_update_network,
            'add_element': self._handle_add_element,
            'remove_element': self._handle_remove_element,
            'delete_network': self._handle_delete_network,
            'activate_network': self._handle_activate_network,
            'activation_status': self._handle_activation_status,
            'activation_snapshot': self._handle_activation_snapshot,
            'activation_details': self._handle_activation_details
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping.keys():
            action_function = action_mapping[action]
            action_execution_status = action_function(param)
        return action_execution_status

    def _process_parameters(self, endpoint, params):
        """ This function is used process the parameters and creates a valid endpoint URL.
        :param endpoint: The endpoint we want to send data to
        :param param: Dictionary of input parameters
        :return: endpoint
        """
        # Default values
        first_param = True

        if len(params) > 0:
            endpoint += "?"

            for param, value in params.items():
                if first_param:
                    endpoint += "{}={}".format(param, value)
                    first_param = False
                else:
                    endpoint += "&{}={}".format(param, value)
        else:
            endpoint = endpoint

        return endpoint

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get('base_url')
        self._client_token = config.get('client_token')
        self._client_secret = config.get('client_secret')
        self._access_token = config.get('access_token')

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    # import pudb
    import argparse

    # pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            login_url = AkamaiNetworkListsConnector._get_phantom_base_url() + '/login'

            print ("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print ("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = AkamaiNetworkListsConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
