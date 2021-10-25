# File: googlepeople_connector.py
#
# Copyright (c) 2021 Splunk Inc.
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
# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import phantom.utils as ph_utils

from googlepeople_consts import *

import requests
import os
import json
from google.oauth2 import service_account
from bs4 import UnicodeDammit
from html import unescape
from googleapiclient import discovery
from googleapiclient.errors import HttpError

init_path = '{}/dependencies/google/__init__.py'.format(
    os.path.dirname(os.path.abspath(__file__))
)
try:
    open(init_path, 'a+').close()
except:
    pass


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

            if parameter <= 0:
                return action_result.set_status(phantom.APP_ERROR, INVALID_NON_ZERO_NON_NEGATIVE_INTEGER_ERR_MSG.format(key)), None

        return phantom.APP_SUCCESS, parameter

    def _create_client(self, action_result, scopes):
        credentials = None
        try:
            credentials = service_account.Credentials.from_service_account_info(self._key_dict, scopes=scopes)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to get the credentials from the key json. {}".format(err_msg)), None)

        if self._login_email:
            try:
                credentials = credentials.with_subject(self._login_email)
            except Exception as e:
                err_msg = self._get_error_message_from_exception(e)
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Failed to create delegated credentials. {}".format(err_msg)), None)

        try:
            client = discovery.build('people', 'v1', credentials=credentials)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to create client. {}".format(err_msg)), None)

        return RetVal(phantom.APP_SUCCESS, client)

    def _paginator(self, client, fields, limit):

        """
        This method repeatedly makes API calls until the requested number of records are fetched from the server.

        :param client: The object of google client API
        :param fields: The fields to be fetched
        :param limit: The number of records to be fetched
        """

        kwargs = dict()
        list_items = list()
        page_token = None
        action_id = self.get_action_identifier()
        kwargs.update({'pageSize': 1000})

        while True:
            if page_token:
                kwargs.update({"pageToken": page_token})

            if action_id == "list_other_contacts":
                kwargs.update({'readMask': fields})
                response = client.otherContacts().list(**kwargs).execute()
                if response.get("otherContacts"):
                    list_items.extend(response.get("otherContacts"))

            elif action_id == "list_directory":
                kwargs.update({'sources': ['DIRECTORY_SOURCE_TYPE_DOMAIN_CONTACT', 'DIRECTORY_SOURCE_TYPE_DOMAIN_PROFILE']})
                kwargs.update({'readMask': fields})
                response = client.people().listDirectoryPeople(**kwargs).execute()
                if response.get("people"):
                    list_items.extend(response.get("people"))

            elif action_id == "list_people":
                kwargs.update({'sources': ['READ_SOURCE_TYPE_CONTACT']})
                kwargs.update({'personFields': fields})
                response = client.people().connections().list(resourceName='people/me', **kwargs).execute()
                if response.get("connections"):
                    list_items.extend(response.get("connections"))

            if limit and len(list_items) >= limit:
                return list_items[:limit]
            page_token = response.get('nextPageToken')
            if not page_token:
                break

        return list_items

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        scopes = [GOOGLE_CONTACTS_SCOPE]

        self.save_progress("Creating Google People client...")
        ret_val, client = self._create_client(action_result, scopes)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Getting list of connections for {}".format(self._login_email))
        try:
            client.people().connections().list(resourceName='people/me', personFields='names,emailAddresses').execute()
        except Exception as e:
            self.save_progress("Test Connectivity Failed")
            err_msg = unescape(UnicodeDammit(self._get_error_message_from_exception(e)).unicode_markup.encode('utf-8').decode('unicode_escape'))
            return action_result.set_status(phantom.APP_ERROR, "Error while listing connections. {}".format(err_msg))

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_other_contacts(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        scopes = [GOOGLE_OTHER_CONTACTS_SCOPE_READ_ONLY]

        ret_val, client = self._create_client(action_result, scopes)

        if phantom.is_fail(ret_val):
            self.debug_print(GOOGLE_CREATE_CLIENT_FAILED_MSG)
            return action_result.get_status()

        read_mask = param.get('read_mask', 'names,emailAddresses')

        # Validation for comma-separated value
        masks = [x.strip() for x in read_mask.split(",")]
        masks = list(filter(None, masks))

        if not masks:
            return action_result.set_status(phantom.APP_ERROR, INVALID_COMMA_SEPARATED_ERR_MSG.format('read mask'))

        read_mask = ",".join(masks)

        limit = param.get('limit')
        # Validate 'limit' action parameter
        ret_val, limit = self._validate_integer(action_result, limit, LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            otherContacts = self._paginator(client, read_mask, limit)
        except HttpError as e:
            if "_get_reason" in dir(e):
                return action_result.set_status(phantom.APP_ERROR, "{}. {}".format(GOOGLE_LIST_OTHER_CONTACTS_FAILED_MSG, e._get_reason()))
            err_msg = self._get_error_message_from_exception(e)
            self.debug_print("Exception message: {}".format(err_msg))
            return action_result.set_status(phantom.APP_ERROR, GOOGLE_LIST_OTHER_CONTACTS_FAILED_MSG)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            self.debug_print("Exception message: {}".format(err_msg))
            return action_result.set_status(phantom.APP_ERROR, GOOGLE_LIST_OTHER_CONTACTS_FAILED_MSG)

        num_otherContacts = len(otherContacts)

        for contact in otherContacts:
            action_result.add_data(contact)

        action_result.update_summary({'total_otherContacts_returned': num_otherContacts})

        return action_result.set_status(
            phantom.APP_SUCCESS, 'Successfully retrieved {} otherContact{}'.format(
                num_otherContacts, '' if num_otherContacts == 1 else 's'
            )
        )

    def _handle_copy_contact(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        scopes = [GOOGLE_CONTACTS_SCOPE, GOOGLE_OTHER_CONTACTS_SCOPE_READ_ONLY]

        ret_val, client = self._create_client(action_result, scopes)

        if phantom.is_fail(ret_val):
            self.debug_print(GOOGLE_CREATE_CLIENT_FAILED_MSG)
            return action_result.get_status()

        resource_name = param['resource_name']
        if OTHER_CONTACTS_RESOURCE_NAME_PREFIX not in resource_name:
            return action_result.set_status(phantom.APP_ERROR, "Resource name of contact to be copied must be 'otherContact'")

        data = {}

        copy_mask = param.get('copy_mask', 'names,emailAddresses,phoneNumbers')

        # Validation for comma-separated value
        masks = [x.strip() for x in copy_mask.split(",")]
        masks = list(filter(None, masks))

        if not masks:
            return action_result.set_status(phantom.APP_ERROR, INVALID_COMMA_SEPARATED_ERR_MSG.format('copy mask'))

        copy_mask = ",".join(masks)

        data.update({'copyMask': copy_mask})

        try:
            response = client.otherContacts().copyOtherContactToMyContactsGroup(resourceName=resource_name, body=data).execute()
        except HttpError as e:
            if "_get_reason" in dir(e):
                return action_result.set_status(phantom.APP_ERROR, "{}. {}".format(GOOGLE_COPY_CONTACT_FAILED_MSG, e._get_reason()))
            err_msg = self._get_error_message_from_exception(e)
            self.debug_print("Exception message: {}".format(err_msg))
            return action_result.set_status(phantom.APP_ERROR, GOOGLE_COPY_CONTACT_FAILED_MSG)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            self.debug_print("Exception message: {}".format(err_msg))
            return action_result.set_status(phantom.APP_ERROR, GOOGLE_COPY_CONTACT_FAILED_MSG)

        action_result.add_data(response)

        action_result.update_summary({'total_contacts_copied': 1})

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully copied 1 contact')

    def _handle_list_directory(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        scopes = [GOOGLE_DIRECTORY_SCOPE_READ_ONLY]

        ret_val, client = self._create_client(action_result, scopes)

        if phantom.is_fail(ret_val):
            self.debug_print(GOOGLE_CREATE_CLIENT_FAILED_MSG)
            return action_result.get_status()

        read_mask = param.get('read_mask', 'names,emailAddresses')

        # Validation for comma-separated value
        masks = [x.strip() for x in read_mask.split(",")]
        masks = list(filter(None, masks))

        if not masks:
            return action_result.set_status(phantom.APP_ERROR, INVALID_COMMA_SEPARATED_ERR_MSG.format('read mask'))

        read_mask = ",".join(masks)

        limit = param.get('limit')
        # Validate 'limit' action parameter
        ret_val, limit = self._validate_integer(action_result, limit, LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            directoryPeople = self._paginator(client, read_mask, limit)
        except HttpError as e:
            if "_get_reason" in dir(e):
                return action_result.set_status(phantom.APP_ERROR, "{}. {}".format(GOOGLE_LIST_DIRECTORY_FAILED_MSG, e._get_reason()))
            err_msg = self._get_error_message_from_exception(e)
            self.debug_print("Exception message: {}".format(err_msg))
            return action_result.set_status(phantom.APP_ERROR, GOOGLE_LIST_DIRECTORY_FAILED_MSG)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            self.debug_print("Exception message: {}".format(err_msg))
            return action_result.set_status(phantom.APP_ERROR, GOOGLE_LIST_DIRECTORY_FAILED_MSG)

        num_directoryPeople = len(directoryPeople)
        action_result.update_summary({'total_people_returned': num_directoryPeople})

        for person in directoryPeople:
            action_result.add_data(person)

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
        if resource_name.startswith('otherContacts/'):
            return action_result.set_status(phantom.APP_ERROR, "This action cannot be performed on otherContacts")

        ret_val, client = self._create_client(action_result, scopes)

        if phantom.is_fail(ret_val):
            self.debug_print(GOOGLE_CREATE_CLIENT_FAILED_MSG)
            return action_result.get_status()

        kwargs = {'sources': ['READ_SOURCE_TYPE_CONTACT']}

        person_fields = param.get('person_fields', 'names,emailAddresses')

        # Validation for comma-separated value
        fields = [x.strip() for x in person_fields.split(",")]
        fields = list(filter(None, fields))

        if not fields:
            return action_result.set_status(phantom.APP_ERROR, INVALID_COMMA_SEPARATED_ERR_MSG.format('person fields'))

        person_fields = ",".join(fields)
        kwargs.update({'personFields': person_fields})

        try:
            response = client.people().get(resourceName=resource_name, **kwargs).execute()
        except HttpError as e:
            if "_get_reason" in dir(e):
                return action_result.set_status(phantom.APP_ERROR, "{}. {}".format(GOOGLE_GET_USER_PROFILE_FAILED_MSG, e._get_reason()))
            err_msg = self._get_error_message_from_exception(e)
            self.debug_print("Exception message: {}".format(err_msg))
            return action_result.set_status(phantom.APP_ERROR, GOOGLE_GET_USER_PROFILE_FAILED_MSG)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            self.debug_print("Exception message: {}".format(err_msg))
            return action_result.set_status(phantom.APP_ERROR, GOOGLE_GET_USER_PROFILE_FAILED_MSG)

        action_result.add_data(response)

        action_result.update_summary({'resource_id_returned': response.get('resourceName')})

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved user profile")

    def _handle_list_people(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        scopes = [GOOGLE_CONTACTS_SCOPE]

        ret_val, client = self._create_client(action_result, scopes)

        if phantom.is_fail(ret_val):
            self.debug_print(GOOGLE_CREATE_CLIENT_FAILED_MSG)
            return action_result.get_status()

        person_fields = param.get('person_fields', 'names,emailAddresses')

        # Validation for comma-separated value
        fields = [x.strip() for x in person_fields.split(",")]
        fields = list(filter(None, fields))

        if not fields:
            return action_result.set_status(phantom.APP_ERROR, INVALID_COMMA_SEPARATED_ERR_MSG.format('person fields'))

        person_fields = ",".join(fields)

        limit = param.get('limit')
        # Validate 'limit' action parameter
        ret_val, limit = self._validate_integer(action_result, limit, LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            people = self._paginator(client, person_fields, limit)
        except HttpError as e:
            if "_get_reason" in dir(e):
                return action_result.set_status(phantom.APP_ERROR, "{}. {}".format(GOOGLE_LIST_PEOPLE_FAILED_MSG, e._get_reason()))
            err_msg = self._get_error_message_from_exception(e)
            self.debug_print("Exception message: {}".format(err_msg))
            return action_result.set_status(phantom.APP_ERROR, GOOGLE_LIST_PEOPLE_FAILED_MSG)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            self.debug_print("Exception message: {}".format(err_msg))
            return action_result.set_status(phantom.APP_ERROR, GOOGLE_LIST_PEOPLE_FAILED_MSG)

        for person in people:
            action_result.add_data(person)

        num_people = len(people)
        action_result.update_summary({'total_people_returned': num_people})

        return action_result.set_status(
            phantom.APP_SUCCESS, 'Successfully retrieved {} user{}'.format(num_people, '' if num_people == 1 else 's')
        )

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id: {}".format(self.get_action_identifier()))

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
            self._key_dict = json.loads(key_json)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            self.debug_print("Exception message: {}".format(err_msg))
            return self.set_status(phantom.APP_ERROR, "Please provide a valid value for the 'Contents of service account JSON file' asset configuration parameter")

        self._login_email = config['login_email']

        if not ph_utils.is_email(self._login_email):
            return self.set_status(phantom.APP_ERROR, "Please provide a valid value for the 'Login email' asset configuration parameter")

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
        login_url = BaseConnector._get_phantom_base_url() + '/login'
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
