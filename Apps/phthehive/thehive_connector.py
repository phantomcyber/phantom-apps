# File: thehive_connector.py
# Copyright (c) 2018-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import phantom.rules as ph_rules

# Usage of the consts file is recommended
from thehive_consts import *
import requests
import json
import magic
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class ThehiveConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(ThehiveConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_reponse(self, response, action_result):

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

        message = message.replace('{', '{{').replace('}', '}}')

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
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        try:
            if resp_json.get('errors', [])[0][0].get('message'):
                message = "Error from server. Status Code: {0} Data from server: {1}".format(
                    r.status_code, resp_json.get('errors', [])[0][0].get('message'))
        except:
            pass
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

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get", files=None):

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            if not files:
                r = request_func(
                            url,
                            json=data,
                            headers=headers,
                            verify=config.get('verify_server_cert', False),
                            params=params,
                            files=files)
            else:
                r = request_func(
                            url,
                            data=data,
                            headers=headers,
                            verify=config.get('verify_server_cert', False),
                            params=params,
                            files=files)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        authToken = "Bearer " + self._api_key

        self.save_progress("Connecting to endpoint")
        # make rest call
        headers = {'Authorization': authToken}
        ret_val, response = self._make_rest_call('api/case', action_result, params=None, headers=headers)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_ticket(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        data = dict()
        fields = dict()

        ret_val, fields = self._get_fields(param, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if (fields):
            data.update(fields)

        title = param['title']
        description = param['description']
        data.update({'title': title, 'description': description})

        # Optional values should use the .get() function

        severity = param.get('severity', 'Medium')
        try:
            int_severity = THEHIVE_SEVERITY_DICT[severity]
        except KeyError:
            return action_result.set_status(phantom.APP_ERROR, THEHIVE_ERR_INVALID_SEVERITY)
        data.update({'severity': int_severity})

        tlp = param.get('tlp', 'Amber')
        try:
            int_tlp = THEHIVE_TLP_DICT[tlp]
        except KeyError:
            return action_result.set_status(phantom.APP_ERROR, THEHIVE_ERR_INVALID_TLP)
        data.update({'tlp': int_tlp})

        if 'owner' in param:
            data.update({'owner': param['owner']})

        # make rest call
        authToken = "Bearer " + self._api_key
        headers = {'Content-Type': 'application/json', 'Authorization': authToken}
        ret_val, response = self._make_rest_call('api/case', action_result, params=None, data=data, headers=headers, method="post")

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        action_result.add_data(response)
        action_result.update_summary({'new_case_id': response['caseId']})
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully created a new case")

    def _handle_get_ticket(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        case_id = param['id']

        # make rest call
        endpoint = "api/case/" + case_id
        authToken = "Bearer " + self._api_key
        headers = {'Content-Type': 'application/json', 'Authorization': authToken}
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=headers)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # summary = action_result.update_summary(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully got Ticket")

    def _handle_update_ticket(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        data = dict()
        fields = dict()
        case_id = param['id']
        ret_val, fields = self._get_fields(param, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if (fields):
            data.update(fields)

        endpoint = "api/case/" + case_id
        authToken = "Bearer " + self._api_key
        headers = {'Content-Type': 'application/json', 'Authorization': authToken}
        ret_val, response = self._make_rest_call(endpoint, action_result, data=data, params=None, headers=headers, method="patch")

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully updated Ticket")

    def _handle_list_tickets(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        authToken = "Bearer " + self._api_key
        headers = {'Authorization': authToken}
        params = {'range': 'all'}
        ret_val, response = self._make_rest_call('api/case', action_result, params=params, headers=headers)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        # action_result.add_data(response)
        for ticket in response:
            action_result.add_data(ticket)

        summary = action_result.set_summary({})
        summary['num_tickets'] = len(response)
        # Add a dictionary that is made up of the most important values from data into the summary

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_task(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        case_id = param['id']
        title = param['title']
        status = param['status']
        data = dict()
        data.update({'title': title, 'status': status})
        endpoint = 'api/case/' + case_id + '/task'
        authToken = "Bearer " + self._api_key
        headers = {'Content-Type': 'application/json', 'Authorization': authToken}
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, data=data, headers=headers,
                                                 method="post")
        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully created Tasks")

    def _handle_search(self, param, path):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        if path == "ticket":
            search = param['search_ticket']
            endpoint = 'api/case/_search'
        else:
            search = param['search_task']
            endpoint = 'api/case/task/_search'
        data = dict()

        # Fetch all the items matching the search criteria
        params = {'range': 'all'}

        try:
            search = json.loads(search)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, THEHIVE_ERR_FIELDS_JSON_PARSE, e)
        data.update(search)
        authToken = "Bearer " + self._api_key
        headers = {'Content-Type': 'application/json', 'Authorization': authToken}
        ret_val, response = self._make_rest_call(endpoint, action_result, params=params, data=data, headers=headers,
                                                    method="post")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        for ticket in response:
            action_result.add_data(ticket)

        summary = action_result.set_summary({})
        summary['num_results'] = len(response)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_task(self, param, path):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        data = dict()
        task_id = param['task_id']
        title = param.get('task_title')
        owner = param.get('task_owner')
        status = param.get('task_status')
        description = param.get('task_description')

        if (title):
            data.update({'title': title})
        if (owner):
            data.update({'owner': owner})
        if (status):
            data.update({'status': status})
        if (description):
            data.update({'description': description})

        endpoint = "api/case/task/" + task_id
        authToken = "Bearer " + self._api_key
        headers = {'Content-Type': 'application/json', 'Authorization': authToken}
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=headers, data=data, method="patch")

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # summary = action_result.update_summary(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully updated Task")

    def _get_fields(self, param, action_result):

        fields = param.get('fields')

        # fields is an optional field
        if (not fields):
            return RetVal(phantom.APP_SUCCESS, None)

        # we take in as a dictionary string, first try to load it as is
        try:
            fields = json.loads(fields)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, THEHIVE_ERR_FIELDS_JSON_PARSE, e), None)

        return RetVal(phantom.APP_SUCCESS, fields)

    def _handle_get_observables(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        case_id = param.get('ticket_id')
        data_type = param.get('data_type')

        # make rest call
        endpoint = "api/case/artifact/_search"
        authToken = "Bearer " + self._api_key
        headers = {'Content-Type': 'application/json', 'Authorization': authToken}
        data = {"query": { "_parent": { "_type": "case", "_query": { "_id": case_id}}}}
        ret_val, response = self._make_rest_call(endpoint, action_result, data=data, params=None, method="post", headers=headers)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if data_type:
            response_formatted = [responses for responses in response if responses.get('dataType') == data_type]
        else:
            response_formatted = response

        for resp in response_formatted:
            if 'attachment' in resp and 'hashes' in resp.get('attachment'):
                hashes = resp.get('attachment').get('hashes')
                if len(hashes) > 0:
                    resp['attachment']['sha256'] = hashes[0]
                    resp['attachment']['sha1'] = hashes[1]
                    resp['attachment']['md5'] = hashes[2]

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        action_result.add_data(response_formatted)

        return action_result.set_status(phantom.APP_SUCCESS, "Num observables found: {}".format(len(response_formatted)))

    # Now post process the data,  uncomment code as you deem fit
    def _handle_create_observable(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        data = dict()
        case_id = param['id']
        data_type = param['data_type']
        message = param['description']
        tlp = param.get('tlp', 'Amber')
        try:
            int_tlp = THEHIVE_TLP_DICT[tlp]
        except KeyError:
            return action_result.set_status(phantom.APP_ERROR, THEHIVE_ERR_INVALID_TLP)
        tags = param.get('tags', '')
        try:
            tags = [x.strip() for x in tags.split(',')]
            tags = list(filter(None, tags))
        except:
            return action_result.set_status(phantom.APP_ERROR, "Tags format invalid. Please supply one or more tags separated by a comma")

        ioc = param.get('ioc', False)
        data = param.get('data', '')

        # if a file is to be supplied, the vault_id parameter will be used to grab a file from the Vault
        if data_type == 'file':
            vault_id = param.get('vault_id')

            if not vault_id:
                return action_result.set_status(phantom.APP_ERROR, "Parameter Vault ID is mandatory if data_type is file")

            _, _, vault_file_info = ph_rules.vault_info(container_id=self.get_container_id(), vault_id=vault_id)

            if len(list(vault_file_info)) != 1:
                return action_result.set_status(phantom.APP_ERROR, "Unable to find specified Vault file. Please check Vault ID and try again.")

            vault_file_info = list(vault_file_info)[0]
            file_path = vault_file_info.get('path')
            file_name = vault_file_info.get('name')

            # file name is being ignored by Hive. It uses the file_path.
            file_data = {'attachment': (file_name, open(file_path, 'rb'), magic.Magic(mime=True).from_file(file_path))}

        endpoint = "api/case/{0}/artifact".format(case_id)
        authToken = "Bearer " + self._api_key
        headers = {'Authorization': authToken}
        mesg = {
            "dataType": data_type,
            "message": message,
            "tlp": int_tlp,
            "tags": tags,
            "ioc": ioc
        }

        if data_type == 'file':
            data = {"_json": json.dumps(mesg)}

            ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=headers, data=data, method="post", files=file_data)
        else:
            mesg['data'] = data
            headers['Content-Type'] = 'application/json'
            ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=headers, data=mesg, method="post")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # need to flatten hashes if file was uploaded
        if response.get('attachment'):
            hashes = response.get('attachment').get('hashes')
            response['attachment']['sha256'] = hashes[0]
            response['attachment']['sha1'] = hashes[1]
            response['attachment']['md5'] = hashes[2]

            del response['attachment']['hashes']

        # Add the response into the data section
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully created Observable")

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'create_ticket':
            ret_val = self._handle_create_ticket(param)

        elif action_id == 'get_ticket':
            ret_val = self._handle_get_ticket(param)

        elif action_id == 'update_ticket':
            ret_val = self._handle_update_ticket(param)

        elif action_id == 'list_tickets':
            ret_val = self._handle_list_tickets(param)

        elif action_id == 'create_task':
            ret_val = self._handle_create_task(param)

        elif action_id == 'search_ticket':
            ret_val = self._handle_search(param, "ticket")

        elif action_id == 'search_task':
            ret_val = self._handle_search(param, "task")

        elif action_id == 'update_task':
            ret_val = self._handle_update_task(param, "task")

        elif action_id == 'get_observables':
            ret_val = self._handle_get_observables(param)

        elif action_id == 'create_observable':
            ret_val = self._handle_create_observable(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()
        config = self.get_config()
        self._base_url = config['base_url']
        if not self._base_url.endswith('/'):
            self._base_url = self._base_url + "/"

        self._api_key = config['api_key']

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

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
            login_url = ThehiveConnector._get_phantom_base_url() + '/login'
            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ThehiveConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
