# File: mfservicemanager_connector.py
# Copyright (c) 2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL – Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from mfservicemanager_consts import *
import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class MfServiceManagerConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(MfServiceManagerConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, u"Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = u'\n'.join(split_lines)
        except:
            error_text = u"Cannot parse error details"

        message = u"Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace(u'{', u'{{').replace(u'}', u'}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, u"Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = u"Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace(u'{', u'{{').replace(u'}', u'}}'))

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
        message = u"Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, u"Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                            url,
                            auth=(self._username, self._password),  # basic authentication
                            verify=config.get('verify_server_cert', False),
                            **kwargs)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, u"Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Retrieving list of incidents...")
        ret_val, response = self._make_rest_call(HPSM_INCIDENTS_ENDPOINT, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed.")
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
        assignment_group = param.get('assignment group', '')
        fields = param.get('fields', '')
        try:
            if not len(fields):
                fields = '{}'
            fields = json.loads(fields)
        except:
            return action_result.set_status(phantom.APP_ERROR, "fields is not a valid JSON string. Please validate and try running the action again.")

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

        id = param['id']
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

        id = param['id']
        endpoint = HPSM_GET_RESOURCE.format(id=id, project_key='incidents')
        update_fields = {
            'Assignee': param['Assignee']
        }

        if param.get('Description'):
            update_fields['Description'] = param.get('Description')

        if param.get('Assignment Group'):
            update_fields['Assignment Group'] = param.get('Assignment Group')

        if param.get('Title'):
            update_fields['Title'] = param.get('Title')

        if param.get('Category'):
            update_fields['Category'] = param.get('Category')

        if param.get('Contact'):
            update_fields['Contact'] = param.get('Contact')

        if param.get('Impact'):
            update_fields['Impact'] = str(param.get('Impact'))

        if param.get('Urgency'):
            update_fields['Urgency'] = str(param.get('Urgency'))

        if param.get('Affected CI'):
            update_fields['AffectedCI'] = param.get('Affected CI')

        if param.get('Area'):
            update_fields['Area'] = param.get('Area')

        if param.get('Subarea'):
            update_fields['Subarea'] = param.get('Subarea')

        journal_updates = [
            journal_update.strip()
            for journal_update
            in param.get('Journal Updates').splitlines()
        ]
        journal_updates = filter(None, journal_updates)

        update_fields['JournalUpdates'] = journal_updates

        if param.get('Service'):
            update_fields['Service'] = param.get('Service')

        if param.get('Ticket Source'):
            update_fields['mmmTicketSource'] = param.get('Ticket Source')

        update_obj = {
            'Incident': update_fields
        }

        # update object
        ret_val, response = self._make_rest_call(endpoint, action_result, method='put', json=update_obj)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # grab relevant fields from return JSON
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

        id = param['id']
        assignee = param['assignee']
        closure_code = param['closure code']
        solution = [solution_line.strip() for solution_line in param['solution'].splitlines()]
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
        noeffect = param.get('no implementation effect', '')
        noeffect = noeffect.splitlines()

        title = param.get('title', '')
        service = param.get('service', '')
        # risk_assessment = param.get('risk assessment', '')
        change_coordinator = param.get('change coordinator', '')
        category = param.get('category', '')
        subcategory = param.get('subcategory', '')
        impact = param.get('impact', '')
        reason = param.get('reason', '')
        planned_end = param.get('implementation end', '')
        planned_start = param.get('implementation start', '')
        assignment_group = param.get('assignment group', '')
        fields = param.get('fields', '')
        try:
            if not len(fields):
                fields = '{}'
            fields = json.loads(fields)
        except:
            return action_result.set_status(phantom.APP_ERROR, "fields is not a valid JSON string. Please validate and try running the action again.")

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

        id = param['id']
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

        id = param['id']
        closure_code = int(param['closure code'])

        closing_comments = [result_line.strip() for result_line in param['closure comments'].splitlines()]
        closing_comments = filter(None, closing_comments)

        review_results = [result_line.strip() for result_line in param['review results'].splitlines()]
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
            fields = json.loads(fields)
        except:
            return action_result.set_status(phantom.APP_ERROR, "fields is not a valid JSON string. Please validate and try running the action again.")

        device = {
            "Device": {
                "AssignmentGroup": param['Assignment Group'],
                "ConfigurationItemType": param['CI Type'],
                "ConfigurationItemSubType": param['CI Subtype'],
                "ContactName": param['Owner Individual'],
                "Department": param['Department'],
                "DepartmentOwner": param['Department Owner'],
                "DisplayName": param['Display Name'],
                "Status": param['Status']
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

        id = param['id']
        project_key = param.get('project_key', 'incidents').lower()
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

        id = param['id']
        update_fields = param.get('update_fields', '')

        try:
            update_fields = json.loads(update_fields)
        except:
            return action_result.set_status(phantom.APP_ERROR, "update_fields is not a valid JSON string. Please validate and try running the action again.")

        project_key = param.get('project_key', 'incidents').lower()
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

        # grab relevant fields from return JSON
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

        id = param['id']
        project_key = param.get('project_key', 'incidents').lower()

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

        elif action_id == 'update_change':
            ret_val = self._handle_update_change(param)

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

        self._base_url = config['base_url']
        if self._base_url.endswith('/'):
            self._base_url = self._base_url[:-1]

        self._username = config['username']
        self._password = config['password']

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
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
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
