# File: rt_connector.py
# Copyright (c) 2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.rules import vault_info
from phantom.vault import Vault

# THIS Connector imports
from requesttracker_consts import *

import requests
import json
import re


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class RTConnector(BaseConnector):

    # actions supported by this script
    ACTION_ID_CREATE_TICKET = "create_ticket"
    ACTION_ID_LIST_TICKETS = "list_tickets"
    ACTION_ID_GET_TICKET = "get_ticket"
    ACTION_ID_UPDATE_TICKET = "update_ticket"
    ACTION_ID_LIST_ATTACHMENTS = "list_attachments"
    ACTION_ID_GET_ATTACHMENT = "get_attachment"
    ACTION_ID_ADD_ATTACHMENT = "add_attachment"

    def __init__(self):

        # Call the BaseConnectors init first
        super(RTConnector, self).__init__()

        self._host = None
        self._session = None
        self._base_url = None
        self._username = None
        self._password = None

    def initialize(self):

        config = self.get_config()

        # Grab config variables
        self._base_url = '{0}/REST/1.0/'.format(config[RT_JSON_DEVICE_URL])
        self._host = self._base_url[config[RT_JSON_DEVICE_URL].find('//') + 2:]
        self._username = config.get(phantom.APP_JSON_USERNAME)
        self._password = config.get(phantom.APP_JSON_PASSWORD)

        # Create a sessions to manage cookies
        self._session = requests.Session()

        # Set validator for ticket and attachment ID inputs
        self.set_validator('rt ticket id', self._is_rt_id)
        self.set_validator('rt attachment id', self._is_rt_id)

        return phantom.APP_SUCCESS

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_text_response(self, response, action_result):

        # A text reponse is expected for every action
        response_text = response.text
        self.debug_print(response_text)

        # The body of the response can be empty
        if response.status_code == 200 and not response_text.strip():
            return RetVal(action_result.set_status(phantom.APP_SUCCESS), response_text)

        # The status code given by response.status_code will be 200 even when certain failures happen
        # This line will extract the actual status code from the body of the response
        status_code = int(re.findall(r'\d{3}', response_text[:response_text.index('\n')])[0])
        self.debug_print(status_code)

        # Please specify the status codes here
        if 200 <= status_code < 399:
            return RetVal(action_result.set_status(phantom.APP_SUCCESS), response_text)

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, response_text)
        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_html_response(self, r, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:  # noqa
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

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
            if 'error' in resp_json:
                return RetVal(action_result.set_status(phantom.APP_ERROR, "API returned an error. Error: {0}".format(resp_json['error'])), None)
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

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

        if 'text' in r.headers.get('Content-Type', ''):
            return self._process_text_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, files=None, method="get"):

        resp_json = None

        try:
            request_func = getattr(self._session, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        if params is None:
            params = {}

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                            url,
                            data=data,
                            files=files,
                            headers=headers,
                            params=params)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        if self.get_action_identifier() == self.ACTION_ID_GET_ATTACHMENT and endpoint.endswith('content'):
            return phantom.APP_SUCCESS, r

        return self._process_response(r, action_result)

    def _create_rt_session(self, action_result):

        params = None
        if self._username and self._password:
            params = {'user': self._username, 'pass': self._password}

        ret_val, response = self._make_rest_call('', action_result, params=params, headers=None)

        return ret_val

    def _is_rt_id(self, rt_id):

        # Check that ticket and attachment IDs are integers
        try:
            if int(rt_id) > 0:
                return True
            else:
                return False
        except:
            return False

    def _test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(param))

        # Progress
        self.save_progress(RT_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Create RT Session
        if phantom.is_fail(self._create_rt_session(action_result)):
            self.save_progress("Test Connectivity Failed")
            return phantom.APP_ERROR

        self.save_progress("Test Connectivity Passed")
        return phantom.APP_SUCCESS

    def _update_ticket(self, param):

        action_result = self.add_action_result(ActionResult(param))

        # Progress
        self.save_progress(RT_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Create RT Session
        if phantom.is_fail(self._create_rt_session(action_result)):
            return phantom.APP_ERROR

        ticket_id = param[RT_JSON_ID]
        fields = param.get(RT_JSON_FIELDS)
        subject = param.get(RT_JSON_SUBJECT)
        comment = param.get(RT_JSON_COMMENT)

        if not any([fields, subject, comment]):
            return action_result.set_status(phantom.APP_ERROR, 'At least one parameter of fields, subject, or comment is required')

        if fields:
            try:
                fields = json.loads(str(fields))
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, 'Fields paramter is not valid JSON', e)
        else:
            fields = {}

        if subject:
            fields['Subject'] = subject

        if fields:

            # Create the content string
            content = {'content': '\n'.join(['{0}: {1}'.format(k, v) for k, v in fields.items()])}

            # Send the edit post request
            ret_val, resp_text = self._make_rest_call('ticket/{0}/edit'.format(ticket_id), action_result, data=content, method='post')

            if phantom.is_fail(ret_val):
                return ret_val

            self.debug_print(resp_text)

            for line in resp_text.split('\n'):
                if line.startswith('#') and 'Unknown field' in line:
                    self.debug_print('WARNING: {0} is an unknown field and was not included in ticket update'.format(line.split(':')[0][2:]))

        if comment:

            self.save_progress('Adding comment')

            # Create the content dictionary
            content = {'content': 'id: {0}\nAction: comment\nText: {1}'.format(ticket_id, comment)}

            # Send the comment post request
            ret_val, resp_text = self._make_rest_call('ticket/{0}/comment'.format(ticket_id), action_result, data=content, method='post')

            if phantom.is_fail(ret_val):
                return ret_val

        self.save_progress("Ticket updated")

        return self._get_ticket_details(ticket_id, action_result)

    def _create_ticket(self, param):

        # Create action result
        action_result = self.add_action_result(ActionResult(param))

        # Create RT object
        if phantom.is_fail(self._create_rt_session(action_result)):
            return action_result.get_status()

        queue = param.get(RT_JSON_QUEUE, DEFAULT_QUEUE)
        subject = param[RT_JSON_SUBJECT]
        text = param[RT_JSON_TEXT]
        priority = param.get(RT_JSON_PRIORITY, DEFAULT_PRIORITY)
        owner = param.get(RT_JSON_OWNER)

        # create the content dictionary
        content = {'content':
            'Queue: {0}\nSubject: {1}\nText: {2} \n \n ---- \n {3}{4}\nPriority: {5}\nOwner: {6}'.format(
                queue, subject, text, RT_TICKET_FOOTNOTE, self.get_container_id(), priority, owner)
        }

        ret_val, resp_text = self._make_rest_call('ticket/new', action_result, data=content, method='post')

        if phantom.is_fail(ret_val):
            return ret_val

        if '# Could not create ticket.' in resp_text:
            if 'Queue not set' in resp_text:
                return action_result.set_status(phantom.APP_ERROR, "Error creating ticket. Invalid queue given.")
            return action_result.set_status(phantom.APP_ERROR, "Error creating ticket. Response from server:\n{0}".format(resp_text))

        ticket_id = None

        for line in resp_text.split('\n'):
            if line.startswith('#'):
                if 'Unknown field' in line:
                    self.debug_print('WARNING: {0} is an unknown field and was not included in ticket creation'.format(line.split(':')[0][2:]))
                else:
                    ticket_id = re.findall(r'\d+', line)[0]

        if not ticket_id:
            return action_result.set_status(phantom.APP_ERROR, "Ticket creation failed")

        self.save_progress(RT_CREATED_TICKET)

        data = {}

        action_result.add_data(data)
        data[RT_JSON_ID] = ticket_id
        data[RT_JSON_SUBJECT] = param[RT_JSON_SUBJECT]

        action_result.set_summary({RT_JSON_NEW_TICKET_ID: ticket_id})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_ticket_details(self, ticket_id, action_result):

        # Query the device for details about the ticket
        ret_val, resp_text = self._make_rest_call("ticket/{0}/show".format(ticket_id), action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        if re.findall('# Ticket .+ does not exist.', resp_text):
            return action_result.set_status(phantom.APP_ERROR, "Ticket {0} does not exist.".format(ticket_id))

        ticket_info = {}

        for line in resp_text.split('\n'):
            if ':' in line:
                spl_line = line.split(':')
                key = spl_line[0]
                value = ':'.join(spl_line[1:])
                ticket_info[key] = value.strip()

        data = {}
        data[RT_JSON_ID] = ticket_id
        data[RT_JSON_QUEUE] = ticket_info.get('Queue')
        data[RT_JSON_OWNER] = ticket_info.get('Owner')
        data[RT_JSON_CREATOR] = ticket_info.get('Creator')
        data[RT_JSON_SUBJECT] = ticket_info.get('Subject')
        data[RT_JSON_STATUS] = ticket_info.get('Status')
        data[RT_JSON_PRIORITY] = ticket_info.get('Priority')
        data[RT_JSON_INITIALPRIORITY] = ticket_info.get('InitialPriority')
        data[RT_JSON_FINALPRIORITY] = ticket_info.get('FinalPriority')
        data[RT_JSON_REQUESTORS] = ticket_info.get('Requestors')
        data[RT_JSON_CC] = ticket_info.get('Cc')
        data[RT_JSON_ADMINCC] = ticket_info.get('AdminCc')
        data[RT_JSON_CREATED] = ticket_info.get('Created')
        data[RT_JSON_STARTS] = ticket_info.get('Starts')
        data[RT_JSON_STARTED] = ticket_info.get('Started')
        data[RT_JSON_DUE] = ticket_info.get('Due')
        data[RT_JSON_RESOLVED] = ticket_info.get('Resolved')
        data[RT_JSON_TOLD] = ticket_info.get('Told')
        data[RT_JSON_TIMEESTIMATED] = ticket_info.get('TimeEstimated')
        data[RT_JSON_TIMEWORKED] = ticket_info.get('TimeWorked')
        data[RT_JSON_TIMELEFT] = ticket_info.get('TimeLeft')

        action_result.add_data(data)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_ticket(self, param):

        # Create action results
        action_result = self.add_action_result(ActionResult(param))

        # Create RT session
        if phantom.is_fail(self._create_rt_session(action_result)):
            return action_result.get_status()

        # get the ticket ID
        ticket_id = param[RT_JSON_ID]

        return self._get_ticket_details(ticket_id, action_result)

    def _list_tickets(self, param):

        # Create the action result
        action_result = self.add_action_result(ActionResult(param))

        # Create RT session
        if phantom.is_fail(self._create_rt_session(action_result)):
            return action_result.get_status()

        queue = param.get(RT_JSON_QUEUE, DEFAULT_QUEUE)
        query = param.get(RT_JSON_QUERY, '').strip()

        if query and not query.startswith('AND'):
            query = ' AND {0}'.format(query)

        # Set up the query
        query = "Queue='{0}'{1}".format(queue, query)

        # Query the device for the list of tickets
        ret_val, resp_text = self._make_rest_call("search/ticket", action_result, params={'query': query})

        if phantom.is_fail(ret_val):
            return ret_val

        if 'No matching results.' in resp_text:
            return action_result.set_status(phantom.APP_SUCCESS, 'Query returned no results')

        # Get ticket ID for each line in response
        tickets = [x.split(':')[0] for x in resp_text.strip().split('\n')[2:]]

        if tickets and "Invalid query" in tickets[0]:
            return action_result.set_status(phantom.APP_ERROR, 'Given query is invalid. Details:\n\n{0}'.format(resp_text))

        # Tickets will be a list of tuples, where the first element will be the ticket ID and the second element will be the subject
        for ticket in tickets:

            ar = ActionResult()

            if phantom.is_fail(self._get_ticket_details(ticket, ar)):
                self.debug_print('Could not get ticket details for ID {0}: {1}'.format(ticket, ar.get_message()))
                continue

            action_result.add_data(ar.get_data()[0])

        action_result.set_summary({RT_TOTAL_ISSUES: len(tickets)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _list_attachments(self, param):

        # Create action result
        action_result = self.add_action_result(ActionResult(param))

        # Create RT object
        if phantom.is_fail(self._create_rt_session(action_result)):
            return action_result.get_status()

        # Grab the ticket ID
        ticket_id = param[RT_JSON_ID]

        # Query the device for the list of attachments of the ticket
        ret_val, resp_text = self._make_rest_call("ticket/{0}/attachments".format(ticket_id), action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        if re.findall('# Ticket .+ does not exist.', resp_text):
            return action_result.set_status(phantom.APP_ERROR, "Ticket {0} does not exist.".format(ticket_id))

        # Find the start of the attachments list
        resp_text = resp_text.strip()
        attachment_index = resp_text.index('Attachments:')

        if attachment_index == -1:
            self.save_progress("No attachments found for ticket id '{0}'".format(ticket_id))
            return action_result.set_status(phantom.APP_SUCCESS)

        # Each attachment it on a separate line in the third "block" of text
        attachments = [x.strip() for x in resp_text[attachment_index:].split('\n')]

        # Set the summary
        action_result.set_summary({'attachments': len(attachments)})

        # No reason to move on if we find no attachments
        if len(attachments) == 0:
            self.save_progress("No attachments found for ticket id '{0}'".format(ticket_id))
            return action_result.set_status(phantom.APP_SUCCESS)

        # The first line of the attachments block starts with "Attachments: "
        attachments[0] = attachments[0][13:]

        # Get the attachment metadata
        # Each line has the form "<attachment_id>: <file_name> (<content_type> / <size>)"
        # The file name could have spaces and parentheses which makes this difficult
        # But the filename will always be bordered by the first colon and the last open paren
        for attachment in attachments:

            data = {}

            data['ticket_id'] = ticket_id
            data['attachment_id'] = re.findall(r'\d+:', attachment)[0][:-1]

            start_path = attachment.find(':') + 2
            end_path = len(attachment) - attachment[::-1].find('(') - 2
            data['path'] = attachment[start_path: end_path]

            split_meta = attachment[end_path + 2:].split('/')
            data['content_type'] = '{0}/{1}'.format(split_meta[0], split_meta[1].strip())
            data['size'] = split_meta[2][:-1 if attachment.endswith(')') else -2].strip()

            action_result.add_data(data)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_attachment(self, param):

        # Create action result
        action_result = self.add_action_result(ActionResult(param))

        # Create RT object
        if phantom.is_fail(self._create_rt_session(action_result)):
            return action_result.get_status()

        # Get parameters
        ticket_id = param[RT_JSON_ID]
        attachment_id = param[RT_JSON_ATTACHMENT]

        # Set up the result data
        data = action_result.add_data(dict())
        data['id'] = ticket_id
        data['attachment_id'] = attachment_id

        # Request the attachment meta data
        ret_val, resp_text = self._make_rest_call("ticket/{0}/attachments/{1}".format(ticket_id, attachment_id), action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        if '# Invalid attachment id' in resp_text:
            return action_result.set_status(phantom.APP_ERROR, "Attachment with ID {0} not found on ticket {1}".format(attachment_id, ticket_id))

        if re.findall('# Ticket .+ does not exist.', resp_text):
            return action_result.set_status(phantom.APP_ERROR, "Ticket {0} does not exist.".format(ticket_id))

        # Look for the filename in the meta data
        filename_index = resp_text.find('filename')

        if filename_index == -1:
            file_name = "noname"
            self.debug_print("Filename not found in header, setting to noname")
        else:
            start_filename = resp_text.find('=', filename_index) + 2
            end_filename = resp_text.find('\n', filename_index) - 1
            file_name = resp_text[start_filename: end_filename]

        if not file_name:
            file_name = "noname"
            self.save_progress("Filename not found in header, setting to noname")

        # Look for the file length in the meta data
        length_index = resp_text.find('Content-Length')

        if length_index == -1:
            return action_result.set_status(phantom.APP_ERROR, "Cannot find Content-Length of attachment")

        start_length = resp_text.find(':', length_index) + 2
        end_length = resp_text.find('\n', length_index)

        length = int(resp_text[start_length: end_length])

        if length == 0:
            return action_result.set_status(phantom.APP_SUCCESS, "File is empty, nothing to do here")

        # Request the attachment content
        ret_val, response = self._make_rest_call("ticket/{0}/attachments/{1}/content".format(ticket_id, attachment_id), action_result)

        # Convert to bytes and strip away headers and trailers.
        content = response.content

        if phantom.is_fail(ret_val):
            return ret_val

        # find first newline
        skip = content.find(b'\n')
        if skip == -1:
            return action_result.set_status(phantom.APP_ERROR, "Cannot find first line of file content")
        # skip first and second newline
        skip += 2

        # Let the actiond handle i/o exceptions and return the errors.
        ret_val = Vault.create_attachment(content[skip:length + skip], self.get_container_id(), file_name=file_name)

        if ret_val['succeeded'] is not True:
            return action_result.set_status(phantom.APP_ERROR, "Error saving file to vault: {0}".format(ret_val.get('error', 'Unknwon error')))

        vault_id = ret_val['vault_id']
        _, _, file_info = vault_info(vault_id=vault_id, container_id=self.get_container_id())

        if len(file_info) == 0:
            return action_result.set_status(phantom.APP_ERROR, "File not found in vault after adding")

        file_info = file_info[0]

        data['vault_id'] = vault_id
        data['name'] = file_info['name']
        data['size'] = file_info['size']
        data['sha1'] = file_info['metadata']['sha1']
        data['sha256'] = file_info['metadata']['sha256']
        data['md5'] = file_info['metadata']['md5']
        data['path'] = file_info['path']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _add_attachment(self, param):

        # Create action result
        action_result = self.add_action_result(ActionResult(param))

        # Create RT object
        if phantom.is_fail(self._create_rt_session(action_result)):
            return action_result.get_status()

        # Get params
        ticket_id = param[RT_JSON_ID]
        vault_id = param[RT_JSON_VAULT]
        comment = param.get('comment')

        # Set default comment
        if not comment:
            comment = 'File uploaded from Phantom'

        # Check for vault file
        _, _, file_info = vault_info(vault_id=vault_id, container_id=self.get_container_id())

        if not file_info:
            return action_result.set_status(phantom.APP_ERROR, "Vault ID is invalid. Vault file not found")

        file_info = file_info[0]

        if not file_info['name']:
            file_info['name'] = vault_id

        # Create payload for request
        content = {'content': 'Action: comment\nText: {0}\nAttachment: {1}'.format(comment, file_info['name'])}
        upfile = {'attachment_1': open(file_info['path'], 'rb')}

        ret_val, resp_text = self._make_rest_call("ticket/{0}/comment".format(ticket_id), action_result, data=content, files=upfile, method='post')

        if phantom.is_fail(ret_val):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """Function that handles all the actions

            Args:

            Return:
                A status code
        """

        # Get the action that we are supposed to carry out, set it in the connection result object
        action = self.get_action_identifier()

        ret_val = phantom.APP_SUCCESS

        if (action == self.ACTION_ID_CREATE_TICKET):
            ret_val = self._create_ticket(param)
        elif (action == self.ACTION_ID_LIST_TICKETS):
            ret_val = self._list_tickets(param)
        elif (action == self.ACTION_ID_GET_TICKET):
            ret_val = self._get_ticket(param)
        elif (action == self.ACTION_ID_UPDATE_TICKET):
            ret_val = self._update_ticket(param)
        elif (action == self.ACTION_ID_LIST_ATTACHMENTS):
            ret_val = self._list_attachments(param)
        elif (action == self.ACTION_ID_GET_ATTACHMENT):
            ret_val = self._get_attachment(param)
        elif (action == self.ACTION_ID_ADD_ATTACHMENT):
            ret_val = self._add_attachment(param)
        elif (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)

        return ret_val


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
            print("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = RTConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
