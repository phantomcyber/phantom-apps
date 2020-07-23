#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import phantom.utils as ph_utils

# Usage of the consts file is recommended
from googlepeople_consts import *

import os
import requests # noqa
import json # noqa
import sys # noqa

init_path = '{}/dependencies/google/__init__.py'.format(  # noqa
    os.path.dirname(os.path.abspath(__file__))  # noqa
)  # noqa
try:
    open(init_path, 'a+').close()  # noqa
except:  # noqa
    pass  # noqa

from google.oauth2 import service_account # noqa

try:
    argv_temp = list(sys.argv)
except:
    pass
sys.argv = ['']

from apiclient.discovery import build # noqa


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class GooglePeopleConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(GooglePeopleConnector, self).__init__()
        self._login_email = None
        self._key_dict = None
        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        # self._base_url = None

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

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

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

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
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get", verify=False):

        resp_json = None
        status_code = None

        try:
            r = requests.get(endpoint=endpoint, headers=headers, params=params, verify=verify)
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, OPENDNSUMB_ERR_SERVER_CONNECTION, e), resp_json, status_code)

        # self.debug_print('REST url: {0}'.format(r.url))

        try:
            resp_json = r.json()
        except:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Response not a valid json"), resp_json, status_code)

        if (r.status_code != requests.codes.ok):  # pylint: disable=E1101
            return (action_result.set_status(phantom.APP_ERROR, status=r.status_code,
                message=self._get_error_message(resp_json, r)), resp_json, status_code)

        return (phantom.APP_SUCCESS, resp_json, status_code)

    def _create_client(self, action_result, scopes):
        credentials = None

        try:
            credentials = service_account.Credentials.from_service_account_info(self._key_dict, scopes=scopes)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to create load the key json", e))

        if(self._login_email):
            try:
                credentials = credentials.with_subject(self._login_email)
            except Exception as e:
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Failed to create delegated credentials", e), None)

        try:
            client = build('people', 'v1', credentials=credentials)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to create client", e), None)

        return RetVal(phantom.APP_SUCCESS, client)

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        scopes = [GOOGLE_CONTACTS_SCOPE]

        self.save_progress("Creating Google People client...")
        ret_val, client = self._create_client(action_result, scopes)

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Test Connectivity Failed.")
            return ret_val

        self.save_progress("Getting list of connections for {}".format(self._login_email))
        try:
            client.people().connections().list('people/me', pageSize=10, personFields='names,emailAddresses')
        except Exception as e:
            self.save_progress("Test Connectivity Failed")
            return action_result.set_status(phantom.APP_ERROR, "Error while listing connections", e)

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_list_other_contacts(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        scopes = [GOOGLE_OTHER_CONTACTS_SCOPE_READ_ONLY]

        ret_val, client = self._create_client(action_result, scopes)

        if phantom.is_fail(ret_val):
            self.debug_print("Failed to create the Google People client")
            return ret_val

        kwargs = {'readMask': 'names,emailAddresses'}

        read_mask = param.get('read_mask')
        if (read_mask):
            kwargs.update({'readMask': read_mask})

        page_token = param.get('page_token')
        if (page_token):
            kwargs.update({'pageToken': read_mask})

        page_size = param.get('page_size', 500)
        if (page_size):
            kwargs.update({'pageSize': page_size})

        request_sync_token = param.get('request_sync_token')
        if (request_sync_token):
            kwargs.update({'requestSyncToken': request_sync_token})

        sync_token = param.get('sync_token')
        if (sync_token):
            kwargs.update({'syncToken': sync_token})

        # # req_url
        # req_url = '{}{}'.format(self._base_url, '/v1/otherContacts')

        # # make rest call
        # ret_val, response = self._make_rest_call(endpoint=req_url, action_result=action_result, params=kwargs, headers=None)

        # if phantom.is_fail(ret_val):
        #     self.debug_print(action_result.get_message())
        #     return self.set_status(phantom.APP_ERROR, action_result.get_message())

        # # Add the response into the data section
        # for otherContact in response['otherContacts']:
        #     action_result.add_data(otherContact)

        try:
            response = client.otherContacts().list(**kwargs).execute()
        except Exception as e:
            error_message = str(e)
            self.debug_print("Exception message: {}".format(error_message))
            return action_result.set_status(phantom.APP_ERROR, "Failed to list other contacts.")

        num_otherContacts = len(response['otherContacts'])

        summary = action_result.update_summary({'total_otherContacts_returned': num_otherContacts})

        next_page = response.get('nextPageToken')
        if (next_page):
            summary['next_page_token'] = next_page

        next_sync = response.get('nextSyncToken')
        if (next_sync):
            summary['next_sync_token'] = next_sync

        return action_result.set_status(
            phantom.APP_SUCCESS, 'Successfully retrieved {} otherContacts{}'.format(
                num_files, '' if num_files == 1 else 's'
            )
        )

    def _handle_copy_contact(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        scopes = [GOOGLE_CONTACTS_SCOPE]

        ret_val, client = self._create_client(action_result, scopes)

        if phantom.is_fail(ret_val):
            self.debug_print("Failed to create the Google People client")
            return ret_val

        resource_name = param['resource_name']

        data = {}

        copy_mask = param.get('copy_mask', 'names,emailAddresses,phoneNumbers')
        if (copy_mask):
            data.update({'copyMask': copy_mask})

        # req_url = '{}/v1/{}:copyOtherContactToMyContactsGroup'.format(self._base_url, resource_name)

        # # make rest call
        # ret_val, response = self._make_rest_call(endpoint=req_url, action_result=action_result, data=json.dumps(data), params=None, headers=None)

        # if phantom.is_fail(ret_val):
        #     self.debug_print(action_result.get_message())
        #     return self.set_status(phantom.APP_ERROR, action_result.get_message())

        try:
            response = client.otherContacts().copyOtherContactToMyContactsGroup(resource_name, body=data).execute()
        except Exception as e:
            error_message = str(e)
            self.debug_print("Exception message: {}".format(error_message))
            return action_result.set_status(phantom.APP_ERROR, "Failed to copy contact.")

        action_result.add_data(response)

        action_result.update_summary({'total_contacts_copied': len(action_result['data'])})

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully copied 1 contact')

    def _handle_list_directory(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        scopes = [GOOGLE_DIRECTORY_SCPOPE_READ_ONLY]

        ret_val, client = self._create_client(action_result, scopes)

        if phantom.is_fail(ret_val):
            self.debug_print("Failed to create the Google People client")
            return ret_val

        kwargs = {'readMask': 'names,emailAddresses', 'sources': ['DIRECTORY_SOURCE_TYPE_DOMAIN_CONTACT', 'DIRECTORY_SOURCE_TYPE_DOMAIN_PROFILE']}

        read_mask = param.get('read_mask')
        if (read_mask):
            kwargs.update({'readMask': read_mask})

        page_size = param.get('page_size', 500)
        if (page_size):
            kwargs.update({'pageSize': page_size})

        page_token = param.get('page_token')
        if (page_token):
            kwargs.update({'pageToken': page_token})

        request_sync_token = param.get('request_sync_token')
        if (request_sync_token):
            kwargs.update({'requestSyncToken': request_sync_token})

        sync_token = param.get('sync_token', '')
        if (sync_token):
            kwargs.update({'syncToken': sync_token})

        try:
            response = client.people().listDirectoryPeople(**kwargs).execute()
        except Exception as e:
            error_message = str(e)
            self.debug_print("Exception message: {}".format(error_message))
            return action_result.set_status(phantom.APP_ERROR, "Failed to list directory.")

        # Add the response into the data section
        directoryPeople = response.get('people', [])
        num_directoryPeople = len(directoryPeople)

        for person in directoryPeople:
            action_result.add_data(person)

        next_page_token = response.get('nextPageToken')
        if (next_page_token):
            summary['next_page_token'] = next_page_token

        next_sync_token = response.get('nextSyncToken')
        if (next_sync_token):
            summary['next_sync_token'] = next_sync_token

        return action_result.set_status(
            phantom.APP_SUCCESS, 'Successfully retrieved {} people{}'.format(
                num_directoryPeople, '' if num_directoryPeople == 1 else 's'
            )
        )

    def _handle_get_user_profile(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        scopes = [GOOGLE_CONTACTS_SCOPE]

        ret_val, client = self._create_client(action_result, scopes)

        if phantom.is_fail(ret_val):
            self.debug_print("Failed to create the Google People client")
            return ret_val

        # Required values can be accessed directly
        resource_name = param['resource_name']

        kwargs = {'person_fields': 'names,emailAddresses'}

        person_fields = param.get('person_fields')
        if (person_fields):
            kwargs.update({'personFields': person_fields})

        try:
            response = client.people().get(resource_name, **kwargs)
        except Exception as e:
            error_message = str(e)
            self.debug_print("Exception message: {}".format(error_message))
            return action_result.set_status(phantom.APP_ERROR, "Failed to get user profile.")

        action_result.add_data(response)

        return action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully retrieved user profile"
        )

    def _handle_list_people(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        scopes = [GOOGLE_CONTACTS_SCOPE]

        ret_val, client = self._create_client(action_result, scopes)

        if phantom.is_fail(ret_val):
            self.debug_print("Failed to create the Google People client")
            return ret_val

        kwargs = {}

        person_fields = param.get('person_fields', 'names,emailAddresses')
        if (person_fields):
            kwargs.update({'personFields': person_fields})

        page_token = param.get('page_token')
        if (page_token):
            kwargs.update({'pageToken': page_token})

        page_size = param.get('page_size', 500)
        if (page_size):
            kwargs.update({'pageSize': page_size})

        request_sync_token = param.get('request_sync_token')
        if (request_sync_token):
            kwargs.update({'requestSyncToken': request_sync_token})

        sync_token = param.get('sync_token')
        if (sync_token):
            kwargs.update({'syncToken': sync_token})

        try:
            response = client.people().connections().list('people/me', **kwargs)
        except Exception as e:
            error_message = str(e)
            self.debug_print("Exception message: {}".format(error_message))
            return action_result.set_status(phantom.APP_ERROR, "Failed to list files.")

        people = response['connections']

        for person in people:
            action_result.add_data(person)

        num_people = response['totalItems']
        summary['total_people'] = num_people

        next_page_token = response.get('nextPageToken')
        if (next_page_token):
            summary['next_page_token'] = next_page_token

        next_sync_token = response.get('nextSyncToken')
        if (next_sync_token):
            summary['next_sync_token'] = next_sync_token

        return action_result.set_status(
            phantom.APP_SUCCESS, 'Successfully retrieved {} users{}'.format(
                num_people, '' if num_people == 1 else 's'
            )
        )

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'list_other_contacts':
            ret_val = self._handle_list_other_contacts(param)

        elif action_id == 'copy_contact':
            ret_val = self._handle_copy_contact(param)

        elif action_id == 'list_directory':
            ret_val = self._handle_list_directory(param)

        elif action_id == 'get_user_profile':
            ret_val = self._handle_get_user_profile(param)

        elif action_id == 'list_people':
            ret_val = self._handle_list_people(param)

        return ret_val

    def initialize(self):
        config = self.get_config()
        self._state = self.load_state()
        key_json = config['key_json']

        try:
            key_dict = json.loads(key_json)
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, "Unable to load the key json", e)

        self._key_dict = key_dict

        login_email = config['login_email']

        if (not ph_utils.is_email(login_email)):
            return self.set_status(phantom.APP_ERROR, "Asset config 'login_email' failed validation")

        self._login_email = login_email

        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import sys
    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('-i', '--input_test_json', help='Input Test JSON file', required=False)
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        login_url = BaseConnector._get_phantom_base_url() + 'login'
        try:
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

        connector = GooglePeopleConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
