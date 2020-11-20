# File: googlepeople_connector.py
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import phantom.utils as ph_utils
from bs4 import UnicodeDammit

# Usage of the consts file is recommended
from googlepeople_consts import *

import requests # noqa

import os
init_path = '{}/dependencies/google/__init__.py'.format(  # noqa
    os.path.dirname(os.path.abspath(__file__))  # noqa
)  # noqa
try:
    open(init_path, 'a+').close()  # noqa
except:  # noqa
    pass  # noqa

import json # noqa
import sys # noqa

from google.oauth2 import service_account # noqa


# the following argv 'work around' is to keep apiclient happy
# and _also_ debug the connector as a script via pudb
try:
    argv_temp = list(sys.argv)
except:
    pass
sys.argv = ['']

#from googleapiclient.discovery import build # noqa
import apiclient # noqa


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

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.
        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """

        try:
            if input_str and self._python_version == 2:
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error messages from the exception.
        :param e: Exception object
        :return: error message
        """

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = ERR_CODE_MSG
                    error_msg = e.args[0]
            else:
                error_code = ERR_CODE_MSG
                error_msg = ERR_MSG_UNAVAILABLE
        except:
            error_code = ERR_CODE_MSG
            error_msg = ERR_MSG_UNAVAILABLE

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = TYPE_ERR_MSG
        except:
            error_msg = ERR_MSG_UNAVAILABLE

        try:
            if error_code in ERR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
        except:
            self.debug_print(PARSE_ERR_MSG)
            error_text = PARSE_ERR_MSG

        return error_text

    def _validate_integer(self, action_result, parameter, key):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, INVALID_INTEGER_ERR_MSG.format(key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, INVALID_INTEGER_ERR_MSG.format(key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, INVALID_NON_NEGATIVE_INTEGER_ERR_MSG.format(key)), None

        return phantom.APP_SUCCESS, parameter

    def _create_client(self, action_result, scopes):
        credentials = None
        try:
            credentials = service_account.Credentials.from_service_account_info(self._key_dict, scopes=scopes)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to get the credentials from the key json", e), None)

        if(self._login_email):
            try:
                credentials = credentials.with_subject(self._login_email)
            except Exception as e:
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Failed to create delegated credentials", e), None)

        try:
            client = apiclient.discovery.build('people', 'v1', credentials=credentials)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to create client", e), None)

        return RetVal(phantom.APP_SUCCESS, client)

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        scopes = [GOOGLE_CONTACTS_SCOPE]

        self.save_progress("Creating Google People client...")
        ret_val, client = self._create_client(action_result, scopes)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return ret_val

        self.save_progress("Getting list of connections for {}".format(self._login_email))
        try:
            client.people().connections().list(resourceName='people/me', personFields='names,emailAddresses').execute() # noqa
        except Exception as e:
            self.save_progress("Test Connectivity Failed")
            return action_result.set_status(phantom.APP_ERROR, "Error while listing connections", e)

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_other_contacts(self, param):
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
            kwargs.update({'pageToken': page_token})

        page_size = param.get('page_size')
        # Validate 'page_size' action parameter
        ret_val, page_size = self._validate_integer(action_result, page_size, PAGE_SIZE_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        if (page_size):
            kwargs.update({'pageSize': page_size})

        request_sync_token = param.get('request_sync_token')
        if (request_sync_token):
            kwargs.update({'requestSyncToken': request_sync_token})

        sync_token = param.get('sync_token')
        if (sync_token):
            kwargs.update({'syncToken': sync_token})

        try:
            response = client.otherContacts().list(**kwargs).execute()
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            self.debug_print("Exception message: {}".format(error_message))
            return action_result.set_status(phantom.APP_ERROR, "Failed to list other contacts")

        otherContacts = response.get('otherContacts', [])
        num_otherContacts = len(otherContacts)

        for contact in otherContacts:
            action_result.add_data(contact)

        summary = action_result.update_summary({'total_otherContacts_returned': num_otherContacts})

        next_page = response.get('nextPageToken')
        if (next_page):
            summary['next_page_token'] = next_page

        next_sync = response.get('nextSyncToken')
        if (next_sync):
            summary['next_sync_token'] = next_sync

        return action_result.set_status(
            phantom.APP_SUCCESS, 'Successfully retrieved {} otherContact{}'.format(
                num_otherContacts, '' if num_otherContacts == 1 else 's'
            )
        )

    def _handle_copy_contact(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        scopes = [GOOGLE_CONTACTS_SCOPE, GOOGLE_OTHER_CONTACTS_SCOPE_READ_ONLY]

        ret_val, client = self._create_client(action_result, scopes)

        if phantom.is_fail(ret_val):
            self.debug_print("Failed to create the Google People client")
            return ret_val

        resource_name = param['resource_name']
        if(OTHER_CONTACTS_RESOURCE_NAME_PREFIX not in resource_name):
            return action_result.set_status(phantom.APP_ERROR, "Resource name of contact to be copied must be 'otherContact'")

        data = {}

        copy_mask = param.get('copy_mask', 'names,emailAddresses,phoneNumbers')
        if (copy_mask):
            data.update({'copyMask': copy_mask})

        try:
            response = client.otherContacts().copyOtherContactToMyContactsGroup(resourceName=resource_name, body=data).execute()
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            self.debug_print("Exception message: {}".format(error_message))
            return action_result.set_status(phantom.APP_ERROR, "Failed to copy contact")

        action_result.add_data(response)

        action_result.update_summary({'total_contacts_copied': 1})

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully copied 1 contact')

    def _handle_list_directory(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

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

        page_size = param.get('page_size')
        # Validate 'page_size' action parameter
        ret_val, page_size = self._validate_integer(action_result, page_size, PAGE_SIZE_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
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
            error_message = self._get_error_message_from_exception(e)
            self.debug_print("Exception message: {}".format(error_message))
            return action_result.set_status(phantom.APP_ERROR, "Failed to list directory")

        directoryPeople = response.get('people', [])
        num_directoryPeople = len(directoryPeople)
        summary = action_result.update_summary({'total_people_returned': num_directoryPeople})

        for person in directoryPeople:
            action_result.add_data(person)

        next_page_token = response.get('nextPageToken')
        if (next_page_token):
            summary['next_page_token'] = next_page_token

        next_sync_token = response.get('nextSyncToken')
        if (next_sync_token):
            summary['next_sync_token'] = next_sync_token

        return action_result.set_status(
            phantom.APP_SUCCESS, 'Successfully retrieved {} {}'.format(
                num_directoryPeople, 'person' if num_directoryPeople == 1 else 'people'
            )
        )

    def _handle_get_user_profile(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        scopes = [GOOGLE_PROFILE_SCOPE, GOOGLE_CONTACTS_SCOPE]

        resource_name = param['resource_name']
        if(resource_name.startswith('otherContacts/')):
            return action_result.set_status(phantom.APP_ERROR, "This action cannot be performed on otherContacts")

        ret_val, client = self._create_client(action_result, scopes)

        if phantom.is_fail(ret_val):
            self.debug_print("Failed to create the Google People client")
            return ret_val

        kwargs = {'sources': ['READ_SOURCE_TYPE_CONTACT']}

        person_fields = param.get('person_fields', 'names,emailAddresses')
        if (person_fields):
            kwargs.update({'personFields': person_fields})

        try:
            response = client.people().get(resourceName=resource_name, **kwargs).execute()
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            self.debug_print("Exception message: {}".format(error_message))
            return action_result.set_status(phantom.APP_ERROR, "Failed to get user profile")

        action_result.add_data(response)

        try:
            action_result.update_summary({'resource_id_returned': response['resourceName']})
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.debug_print(err)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing response from the server")

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved user profile")

    def _handle_list_people(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        scopes = [GOOGLE_CONTACTS_SCOPE]

        ret_val, client = self._create_client(action_result, scopes)

        if phantom.is_fail(ret_val):
            self.debug_print("Failed to create the Google People client")
            return ret_val

        kwargs = {'sources': ['READ_SOURCE_TYPE_CONTACT']}

        person_fields = param.get('person_fields', 'names,emailAddresses')
        if (person_fields):
            kwargs.update({'personFields': person_fields})

        page_token = param.get('page_token')
        if (page_token):
            kwargs.update({'pageToken': page_token})

        page_size = param.get('page_size')
        # Validate 'page_size' action parameter
        ret_val, page_size = self._validate_integer(action_result, page_size, PAGE_SIZE_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        if (page_size):
            kwargs.update({'pageSize': page_size})

        request_sync_token = param.get('request_sync_token')
        if (request_sync_token):
            kwargs.update({'requestSyncToken': request_sync_token})

        sync_token = param.get('sync_token')
        if (sync_token):
            kwargs.update({'syncToken': sync_token})

        try:
            response = client.people().connections().list(resourceName='people/me', **kwargs).execute()
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            self.debug_print("Exception message: {}".format(error_message))
            return action_result.set_status(phantom.APP_ERROR, "Failed to list people")

        try:
            people = response['connections']

            for person in people:
                action_result.add_data(person)

            num_people = response['totalItems']
            summary = action_result.update_summary({'total_people_returned': num_people})
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.debug_print(err)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing response from the server")

        next_page_token = response.get('nextPageToken')
        if (next_page_token):
            summary['next_page_token'] = next_page_token

        next_sync_token = response.get('nextSyncToken')
        if (next_sync_token):
            summary['next_sync_token'] = next_sync_token

        return action_result.set_status(
            phantom.APP_SUCCESS, 'Successfully retrieved {} user{}'.format(
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

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while fetching the Phantom server's Python major version.")

        key_json = config['key_json']

        try:
            key_dict = json.loads(key_json)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.debug_print(err)
            return self.set_status(phantom.APP_ERROR, "Please provide a valid value for the 'Contents of service account JSON file' asset parameter")

        self._key_dict = key_dict

        login_email = config['login_email']

        if (not ph_utils.is_email(login_email)):
            return self.set_status(phantom.APP_ERROR, "Please provide a valid value for the 'Login email' asset parameter")

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

    argparser.add_argument('input_test_json', help='Input Test JSON file')
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

    if (len(sys.argv) < 2):
        print("No test json specified as input")
        exit(0)

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
