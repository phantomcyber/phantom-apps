# File: mfservicemanager_connector.py
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

import requests
import json
from mfservicemanager_consts import *
from bs4 import BeautifulSoup, UnicodeDammit


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class MfServiceManagerConnector(BaseConnector):

    def __init__(self):

        # Call the Base Connector's init first
        super(MfServiceManagerConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _unicode_string_handler(self, input_str):
        """helper method for handling unicode strings

        Arguments:
            input_str  -- Input string that needs to be processed

        Returns:
             -- Processed input string based on input_str
        """
        try:
            if input_str:
                return UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except:
            self.debug_print("Error ocurred while Unicode handling of the string")
        return input_str

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Status code: {0}. Empty response and no information in the header".format(response.status_code)), None)

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
                self._unicode_string_handler(error_text))
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
        error_message = r.text.replace('{', '{{').replace('}', '}}')
        error_message = self._unicode_string_handler(error_message)
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, error_message)

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

        # Process an HTML response, Do this no matter what the API talks.
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
                r.status_code, self._unicode_string_handler(r.text.replace('{', '{{').replace('}', '}}')))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()
        resp_json = None
        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                            url,
                            auth=(self._username, self._password),  # basic authentication
                            verify=config.get('verify_server_cert', False),
                            **kwargs)
        except requests.exceptions.ConnectionError:
            message = 'Error Details: Connection Refused from the Server'
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), resp_json)
        except Exception as e:
            if e.message:
                try:
                    error_msg = self._unicode_string_handler(e.message)
                    message = ('Error connecting to server. Details: {0}').format(error_msg)
                except:
                    return RetVal(action_result.set_status(phantom.APP_ERROR, 'Error connecting to server. Please check the asset configuration parameters.'), resp_json)
            else:
                message = "Error message unavailable. Please check the asset configuration and|or action parameters."
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), resp_json)
        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Retrieving list of incidents...")
        ret_val, response = self._make_rest_call(HPSM_INCIDENTS_ENDPOINT, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_incident(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        title = param.get('title', '')
        description = param.get('description', '')
        # description is stored as a list of lines
        description = description.splitlines()
        service = param.get('service', '')
        area = param.get('area', '')
        subarea = param.get('subarea', '')
        assignment_group = param.get('assignment_group', '')
        fields = param.get('fields', '')
        try:
            if not len(fields):
                fields = '{}'
            fields = json.loads(fields)
        except:
            return action_result.set_status(phantom.APP_ERROR, "'fields' is not a valid JSON string. Please validate and try running the action again.")

        incident = {
            'Incident': {
                'Title': title,
                'Description': description,
                'Service': service,
                'Area': area,
                'Subarea': subarea,
                'AssignmentGroup': assignment_group
            }
        }

        incident['Incident'].update(fields)

        # make rest call
        ret_val, response = self._make_rest_call(HPSM_INCIDENTS_ENDPOINT, action_result, method='post', json=incident)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        resource_data = response.get('Incident', {})

        action_result.add_data(resource_data)

        summary = action_result.update_summary({})
        summary['success'] = response.get('ReturnCode', 0) == 0

        msgs = response.get('Messages', ['Create Failed'])
        if not len(msgs):
            msgs.append('Incident created successfully')

        return action_result.set_status(phantom.APP_SUCCESS, msgs[0])

    def _handle_get_incident(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        id = self._unicode_string_handler(param['id'])
        endpoint = HPSM_GET_RESOURCE.format(id=id, project_key='incidents')

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        resource_data = response.get('Incident', {})

        action_result.add_data(resource_data)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_incident(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        id = self._unicode_string_handler(param['id'])
        endpoint = HPSM_GET_RESOURCE.format(id=id, project_key='incidents')
        update_fields = {
            'Assignee': param['assignee']
        }

        if param.get('description'):
            update_fields['Description'] = param.get('description')

        if param.get('assignment_group'):
            update_fields['AssignmentGroup'] = param.get('assignment_group')

        if param.get('title'):
            update_fields['Title'] = param.get('title')

        if param.get('category'):
            update_fields['Category'] = param.get('category')

        if param.get('contact'):
            update_fields['Contact'] = param.get('contact')

        if param.get('impact'):
            try:
                impact = int(param.get('impact'))
            except:
                return action_result.set_status(phantom.APP_ERROR, "Please provide a valid integer value in the 'impact' parameter")

            update_fields['Impact'] = str(impact)

        if param.get('urgency'):
            try:
                urgency = int(param.get('urgency'))
            except:
                return action_result.set_status(phantom.APP_ERROR, "Please provide a valid integer value in the 'urgency' parameter")

            update_fields['Urgency'] = str(urgency)

        if param.get('affected_ci'):
            update_fields['AffectedCI'] = param.get('affected_ci')

        if param.get('area'):
            update_fields['Area'] = param.get('area')

        if param.get('subarea'):
            update_fields['Subarea'] = param.get('subarea')

        journal_updates = [
            journal_update.strip()
            for journal_update
            in param.get('journal_updates').splitlines()
        ]
        journal_updates = filter(None, journal_updates)

        update_fields['JournalUpdates'] = journal_updates

        if param.get('service'):
            update_fields['Service'] = param.get('service')

        if param.get('ticket_source'):
            update_fields['mmmTicketSource'] = param.get('ticket_source')

        update_obj = {
            'Incident': update_fields
        }

        # update object
        ret_val, response = self._make_rest_call(endpoint, action_result, method='put', json=update_obj)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # grab relevant fields from the returned JSON response
        resource_data = response.get('Incident', {})

        action_result.add_data(resource_data)

        summary = action_result.update_summary({})
        summary['success'] = response.get('ReturnCode', 0) == 0

        msgs = response.get('Messages', ['Update Failed'])
        if not len(msgs):
            msgs.append('Update successful')

        return action_result.set_status(phantom.APP_SUCCESS, msgs[0])

    def _handle_close_incident(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        id = self._unicode_string_handler(param['id'])
        assignee = param['assignee']
        closure_code = param['closure_code']
        solution = [solution_line.strip() for solution_line in self._unicode_string_handler(param['solution']).splitlines()]
        solution = filter(None, solution)
        endpoint = HPSM_CLOSE_RESOURCE.format(id=id, project_key='incidents')

        closure_data = {
            'Incident': {
                'Assignee': assignee,
                'ClosureCode': closure_code,
                'Solution': solution
            }
        }

        # close incident
        ret_val, response = self._make_rest_call(endpoint, action_result, method='post', json=closure_data)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if response.get('Incident'):
            action_result.add_data(response.get('Incident'))
        else:
            action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['success'] = response.get('ReturnCode', 0) == 0

        msgs = response.get('Messages', ['Close Failed'])
        if not len(msgs):
            msgs.append('Close successful')

        return action_result.set_status(phantom.APP_SUCCESS, msgs[0])

    def _handle_create_change(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # description is stored as a list of lines
        description = param.get('description', '')
        description = description.splitlines()

        # noeffect is stored as a list of lines
        noeffect = param.get('no_implementation_effect', '')
        noeffect = noeffect.splitlines()

        title = param.get('title', '')
        service = param.get('service', '')
        # risk_assessment = param.get('risk assessment', '')
        change_coordinator = param.get('change_coordinator', '')
        category = param.get('category', '')
        subcategory = param.get('subcategory', '')
        impact = param.get('impact', '')
        reason = param.get('reason', '')
        planned_end = param.get('implementation_end', '')
        planned_start = param.get('implementation_start', '')
        assignment_group = param.get('assignment_group', '')
        fields = param.get('fields', '')
        try:
            if not len(fields):
                fields = '{}'
            fields = json.loads(fields)
        except:
            return action_result.set_status(phantom.APP_ERROR, "'fields' is not a valid JSON string. Please validate and try running the action again.")

        change = {
            'Change': {
                'Impact': impact,
                # 'RiskAssessment': risk_assessment,
                "EffectOfNotImplementing": noeffect,
                'Service': service,
                'AssignmentGroup': assignment_group,
                'header': {
                    'Title': title,
                    "ChangeCoordinator": change_coordinator,
                    "Category": category,
                    "Subcategory": subcategory,
                    "AssignmentGroup": assignment_group,
                    "Reason": reason,
                    "PlannedEnd": planned_end,
                    "PlannedStart": planned_start,
                },
                'description.structure': {
                    'Description': description
                }
            }
        }

        change.update(fields)

        # make rest call
        ret_val, response = self._make_rest_call(HPSM_CHANGES_ENDPOINT, action_result, method='post', json=change)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        resource_data = response.get('Change', {})

        action_result.add_data(resource_data)

        summary = action_result.update_summary({})
        summary['success'] = response.get('ReturnCode', 0) == 0

        msgs = response.get('Messages', ['Create Failed'])
        if not len(msgs):
            msgs.append('Change created successfully')

        return action_result.set_status(phantom.APP_SUCCESS, msgs[0])

    def _handle_get_change(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        id = self._unicode_string_handler(param['id'])
        endpoint = HPSM_GET_RESOURCE.format(id=id, project_key='changes')

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        change_data = response.get('Change', {})

        action_result.add_data(change_data)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_close_change(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        id = self._unicode_string_handler(param['id'])
        try:
            closure_code = int(param['closure_code'])
        except:
            return action_result.set_status(phantom.APP_ERROR, "Please provide valid numeric value in 'closure_code' action parameter")

        closing_comments = [result_line.strip() for result_line in param['closure_comments'].splitlines()]
        closing_comments = filter(None, closing_comments)

        review_results = [result_line.strip() for result_line in param['review_results'].splitlines()]
        review_results = filter(None, review_results)

        endpoint = HPSM_CLOSE_RESOURCE.format(id=id, project_key='changes')
        closure_data = {
            'Change': {
                'close': {
                    'ClosureCode': closure_code,
                    'ClosingComments': closing_comments
                },
                'ReviewResults': review_results
            }
        }

        # close change
        ret_val, response = self._make_rest_call(endpoint, action_result, method='post', json=closure_data)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if response.get('Change'):
            action_result.add_data(response.get('Change '))
        else:
            action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['success'] = response.get('ReturnCode', 0) == 0

        msgs = response.get('Messages', ['Close Failed'])
        if not len(msgs):
            msgs.append('Close successful')

        return action_result.set_status(phantom.APP_SUCCESS, msgs[0])

    def _handle_create_configitem(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # description is stored as a list of lines
        description = param.get('description', '')
        description = description.splitlines()

        fields = param.get('fields', '')
        try:
            if not len(fields):
                fields = '{}'
            fields = json.loads(fields)
        except:
            return action_result.set_status(phantom.APP_ERROR, "'fields' is not a valid JSON string. Please validate and try running the action again.")

        device = {
            "Device": {
                "AssignmentGroup": param['assignment_group'],
                "ConfigurationItemType": param['ci_type'],
                "ConfigurationItemSubType": param['ci_subtype'],
                "ContactName": param['owner_individual'],
                "Department": param['department'],
                "DepartmentOwner": param['department_owner'],
                "DisplayName": param['display_name'],
                "Status": param['status']
            }
        }

        device.update(fields)

        # make rest call
        ret_val, response = self._make_rest_call(HPSM_CONFIGITEMS_ENDPOINT, action_result, method='post', json=device)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        resource_data = response.get('Device', {})

        action_result.add_data(resource_data)

        summary = action_result.update_summary({})
        summary['success'] = response.get('ReturnCode', 0) == 0

        msgs = response.get('Messages', ['Create Failed'])
        if not len(msgs):
            msgs.append('Config Item created successfully')

        return action_result.set_status(phantom.APP_SUCCESS, msgs[0])

    def _handle_get_object(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        id = self._unicode_string_handler(param['id'])
        project_key = self._unicode_string_handler(param.get('project_key', 'incidents')).lower()
        endpoint = HPSM_GET_RESOURCE.format(id=id, project_key=project_key)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # resource_data = response.get(project_key.capitalize()[:-1], {})

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_object(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        id = self._unicode_string_handler(param['id'])
        update_fields = param.get('update_fields', '')

        try:
            if not len(update_fields):
                update_fields = '{}'
            update_fields = json.loads(update_fields)
        except:
            return action_result.set_status(phantom.APP_ERROR, "'update_fields' is not a valid JSON string. Please validate and try running the action again.")

        project_key = self._unicode_string_handler(param.get('project_key', 'incidents')).lower()
        endpoint = HPSM_GET_RESOURCE.format(id=id, project_key=project_key)

        if not update_fields.get('JournalUpdates'):
            update_fields['JournalUpdates'] = [HPSM_DEFAULT_UPDATE_MESSAGE]

        update_obj = {
            project_key.capitalize()[:-1]: update_fields
        }

        # update object
        ret_val, response = self._make_rest_call(endpoint, action_result, method='put', json=update_obj)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # grab relevant fields from the returned JSON response
        resource_data = response.get(project_key.capitalize()[:-1], {})

        action_result.add_data(resource_data)

        summary = action_result.update_summary({})
        summary['success'] = response.get('ReturnCode', 0) == 0

        msgs = response.get('Messages', ['Update Failed'])
        if not len(msgs):
            msgs.append('Update successful')

        return action_result.set_status(phantom.APP_SUCCESS, msgs[0])

    def _handle_close_object(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        id = self._unicode_string_handler(param['id'])
        project_key = self._unicode_string_handler(param.get('project_key', 'incidents')).lower()

        endpoint = HPSM_CLOSE_RESOURCE.format(id=id, project_key=project_key)

        # close object
        ret_val, response = self._make_rest_call(endpoint, action_result, method='post')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['success'] = response.get('ReturnCode', 0) == 0

        msgs = response.get('Messages', ['Close Failed'])
        if not len(msgs):
            msgs.append('Close successful')

        return action_result.set_status(phantom.APP_SUCCESS, msgs[0])

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'create_incident':
            ret_val = self._handle_create_incident(param)

        elif action_id == 'get_incident':
            ret_val = self._handle_get_incident(param)

        elif action_id == 'update_incident':
            ret_val = self._handle_update_incident(param)

        elif action_id == 'close_incident':
            ret_val = self._handle_close_incident(param)

        elif action_id == 'create_change':
            ret_val = self._handle_create_change(param)

        elif action_id == 'get_change':
            ret_val = self._handle_get_change(param)

        elif action_id == 'close_change':
            ret_val = self._handle_close_change(param)

        elif action_id == 'create_configitem':
            ret_val = self._handle_create_configitem(param)

        elif action_id == 'get_object':
            ret_val = self._handle_get_object(param)

        elif action_id == 'update_object':
            ret_val = self._handle_update_object(param)

        elif action_id == 'close_object':
            ret_val = self._handle_close_object(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._base_url = self._unicode_string_handler(config['base_url'])
        if self._base_url.endswith('/'):
            self._base_url = self._base_url[:-1]

        self._username = self._unicode_string_handler(config['username'])
        self._password = config['password']

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
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
            print ("Accessing the Login page")
            login_url = '{}/login'.format(BaseConnector.get_phantom_base_url())
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
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = MfServiceManagerConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
