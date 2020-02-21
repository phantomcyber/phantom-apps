# File: jira_connector.py
# Copyright (c) 2016-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# --

# Phantom imports
import phantom.app as phantom
from phantom.vault import Vault

# THIS Connector imports
from jira_consts import *
from bs4 import BeautifulSoup

from jira.client import JIRA
from datetime import *

import requests
import tempfile
import signal
import json
import time
import os


def timeout_handler(signum, frame):
    raise Timeout()


class Timeout(Exception):
    pass


class JiraConnector(phantom.BaseConnector):

    # actions supported by this script
    ACTION_ID_CREATE_TICKET = "create_ticket"
    ACTION_ID_LIST_PROJECTS = "list_projects"
    ACTION_ID_LIST_TICKETS = "list_tickets"
    ACTION_ID_GET_TICKET = "get_ticket"
    ACTION_ID_SET_TICKET_STATUS = "set_ticket_status"
    ACTION_ID_UPDATE_TICKET = "update_ticket"
    ACTION_ID_DELETE_TICKET = "delete_ticket"
    ACTION_ID_ADD_COMMENT = "add_comment"
    ACTION_ID_LINK_TICKETS = "link_tickets"
    ACTION_ID_ADD_WATCHER = "add_watcher"
    ACTION_ID_REMOVE_WATCHER = "remove_watcher"
    ACTION_ID_ON_POLL = "on_poll"

    def __init__(self):

        # Call the BaseConnectors init first
        super(JiraConnector, self).__init__()

        self._jira = None

    def initialize(self):

        config = self.get_config()

        # Base URL
        self._base_url = config[JIRA_JSON_DEVICE_URL]
        self._host = self._base_url[self._base_url.find('//') + 2:]

        return phantom.APP_SUCCESS

    def _load_state(self):

        dirpath = os.path.split(os.path.abspath(__file__))[0]
        asset_id = self.get_asset_id()
        state_file_path = "{0}/{1}_state.json".format(dirpath, asset_id)

        state = {}

        try:
            with open(state_file_path, 'r') as f:
                in_json = f.read()
                state = json.loads(in_json)
        except Exception as e:
            self.debug_print("In _load_state: Exception: {0}".format(str(e)))
            pass

        self.debug_print("Loaded state: ", state)

        return state

    def _save_state(self, state):

        self.debug_print("Saving state: ", state)

        dirpath = os.path.split(os.path.abspath(__file__))[0]
        asset_id = self.get_asset_id()
        state_file_path = "{0}/{1}_state.json".format(dirpath, asset_id)

        if (not state_file_path):
            self.debug_print("state_file_path is None in _save_state")
            return phantom.APP_SUCCESS

        try:
            with open(state_file_path, 'w+') as f:
                f.write(json.dumps(state))
        except:
            pass

        return phantom.APP_SUCCESS

    def _set_jira_error(self, result_object, message, e):

        error_text = None

        try:
            error_text = e.text
        except:
            pass

        # Try to parse the HTML content of the error in majority situations and if it fails to parse
        # the error response as HTML, then, return the raw error text to ensure that the error text
        # is not getting dropped from this point
        try:
            soup = BeautifulSoup(str(error_text), "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details. Unparsed error: {0}".format(error_text)

        if "Epic Name is required" in error_text:
            error_text = "{} {}".format(error_text, "Please create a custom field for Epic Name and provide it in the fields parameter as { \"custom_field\" : \"epic_name\" } ")

        return result_object.set_status(phantom.APP_ERROR, "{0}. Message from server: {1}".format(message, error_text))

    def _create_jira_object(self):

        config = self.get_config()

        verify_cert = config[phantom.APP_JSON_VERIFY]

        if (not verify_cert):
            if ('REQUESTS_CA_BUNDLE' in os.environ):
                del os.environ['REQUESTS_CA_BUNDLE']

        # create the options dictionary
        options = {'server': self._base_url, 'verify': verify_cert}

        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(JIRA_START_TIMEOUT)

        try:
            self._jira = JIRA(options=options, basic_auth=(config[phantom.APP_JSON_USERNAME], config[phantom.APP_JSON_PASSWORD]))
        except Timeout:
            return self.set_status(phantom.APP_ERROR, JIRA_ERR_API_TIMEOUT)
        except Exception as e:
            return self._set_jira_error(self, JIRA_ERR_API_INITIALIZATION, e)
        finally:
            signal.alarm(0)

        return phantom.APP_SUCCESS

    def _test_connectivity(self, param):

        # Progress
        self.save_progress(JIRA_USING_BASE_URL.format(base_url=self._base_url))

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Create the jira object
        if (phantom.is_fail(self._create_jira_object())):
            self.append_to_message(JIRA_ERR_CONNECTIVITY_TEST)
            return self.get_status()

        try:
            self._jira.projects()
        except Exception as e:
            self._set_jira_error(self, JIRA_ERR_PROJECTS_INFO, e)
            self.append_to_message(JIRA_ERR_CONNECTIVITY_TEST)
            return self.get_status()

        return self.set_status_save_progress(phantom.APP_SUCCESS, JIRA_SUCC_CONNECTIVITY_TEST)

    def _list_projects(self, param):

        # Progress
        self.save_progress(JIRA_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Create the jira object
        if (phantom.is_fail(self._create_jira_object())):
            return self.get_status()

        action_result = self.add_action_result(phantom.ActionResult(param))

        projects = None

        # get all the projects
        try:
            projects = self._jira.projects()
        except Exception as e:
            return self._set_jira_error(action_result, JIRA_ERR_PROJECTS_INFO, e)

        action_result.set_summary({JIRA_TOTAL_PROJECTS: "0"})

        if (not projects):
            return action_result.set_status(phantom.APP_SUCCESS)

        for project in projects:
            data = action_result.add_data({})
            if hasattr(project, 'key'):
                data[JIRA_JSON_PROJECT_KEY] = project.key
            if hasattr(project, 'id'):
                data[JIRA_JSON_PROJECT_ID] = project.id
            if hasattr(project, 'name'):
                data[JIRA_JSON_PROJECT_NAME] = project.name

        action_result.set_summary({JIRA_TOTAL_PROJECTS: len(projects)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_custom_fields_for_issue(self, issue_id, action_result):

        try:
            edit_meta = self._jira.editmeta(issue_id)
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, "Unable to get edit meta info about the issue", e), None, None)

        fields_meta = edit_meta.get('fields')
        if (not fields_meta):
            return (action_result.set_status(phantom.APP_ERROR,
                "Got empty response to the 'editmeta' REST endpoint. This may be caused by a jira permission problem."), None, None)

        # create an array of custom fields
        try:
            custom_fields = [x for x in fields_meta if ('customfield' in x)]
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, "Unable to parse edit meta info to extract custom fields", e), None, None)

        return (phantom.APP_SUCCESS, custom_fields, fields_meta)

    def _replace_custom_id_with_name(self, input_fields, custom_id_to_name, action_result):

        try:
            # get all the custom keys present in the input_fields
            custom_keys_present = set(input_fields.keys()).intersection(custom_id_to_name.keys())

            for field in custom_keys_present:
                # replace them
                input_fields[custom_id_to_name[field]] = input_fields.pop(field)
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, "Failed to replace custom fields ID with name. Error: {0}".format(str(e))), None, custom_keys_present)

        return (phantom.APP_SUCCESS, input_fields, custom_keys_present)

    def _replace_custom_name_with_id(self, input_fields, custom_name_to_id, action_result):

        try:
            # get all the custom keys present in the input_fields
            custom_keys_present = set(input_fields.keys()).intersection(custom_name_to_id.keys())

            for field in custom_keys_present:
                # replace them
                input_fields[custom_name_to_id[field]] = input_fields.pop(field)
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, "Failed to replace custom fields name with ID. Error: {0}".format(str(e))), None)

        return (phantom.APP_SUCCESS, input_fields)

    def _get_update_fields(self, param, issue_id, action_result, key=JIRA_JSON_UPDATE_FIELDS):

        update_fields = param.get(key)

        # update_fields is an optional field
        if (not update_fields):
            return (phantom.APP_SUCCESS, None)

        # we take in as a dictionary string, first try to load it as is
        try:
            update_fields = json.loads(update_fields)
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR,
                        '{0}. Error: {1}'.format(JIRA_ERR_FIELDS_JSON_PARSE.format(field_name=JIRA_JSON_UPDATE_FIELDS), str(e).replace('{', '(').replace('}', ')'))), None)

        if (not update_fields):
            return (action_result.set_status(phantom.APP_ERROR, "The input dictionary seems to be empty"), None)

        # make a copy of it
        update_fields_copy = dict(update_fields)

        custom_name_to_id = self._get_custom_fields_id_name_map(issue_id, action_result, id_to_name=False)

        # If the custom_fields are empty, no more processing required
        if not custom_name_to_id:
            return (phantom.APP_SUCCESS, update_fields)

        ret_val = True
        fields = update_fields.get('fields')
        if (fields):
            status, fields = self._replace_custom_name_with_id(fields, custom_name_to_id, action_result)
            del update_fields_copy['fields']
            ret_val &= status
            if (not status):
                fields = None

        update = update_fields.get('update')
        if (update):
            status, update = self._replace_custom_name_with_id(update, custom_name_to_id, action_result)
            del update_fields_copy['update']
            ret_val &= status
            if (not status):
                update = None

        # Any more keys left?
        keys = None
        if (update_fields_copy):
            status, keys = self._replace_custom_name_with_id(update_fields_copy, custom_name_to_id, action_result)
            ret_val &= status
            if (not status):
                keys = None

        # Create a new dictionary, because we want to replace all the keys in it
        update_fields_to_ret = {}

        if (fields):
            update_fields_to_ret['fields'] = fields
        if (update):
            update_fields_to_ret['update'] = update
        if (keys):
            update_fields_to_ret.update(keys)

        if (not ret_val):
            return (action_result.get_status(), None)

        return (phantom.APP_SUCCESS, update_fields_to_ret)

    def _set_ticket_status(self, param):

        # Progress
        self.save_progress(JIRA_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Create the jira object
        if (phantom.is_fail(self._create_jira_object())):
            return self.get_status()

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        kwargs = {}

        issue_id = param[JIRA_JSON_ID]

        try:
            issue = self._jira.issue(issue_id)
        except Exception as e:
            return self._set_jira_error(action_result, "Unable to find ticket info. Please make sure the id exist", e)

        if (not issue):
            return action_result.set_status(phantom.APP_ERROR, "Unable to find ticket info. Please make sure the id exist.")

        kwargs.update({'issue': issue_id})

        status_to_set = param[JIRA_JSON_STATUS]

        # get the status' that can be set
        transitions = self._jira.transitions(issue_id)

        try:
            transition_info = [x for x in transitions if x['name'] == status_to_set]
        except:
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse response from server while trying to get information about status values.")

        if (not transition_info):
            message = JIRA_ERR_ISSUE_VALID_TRANSITIONS
            valid_transitions = self._get_list_string(transitions)
            if (valid_transitions):
                message = "{0}. Valid status value(s): {1}".format(message, ', '.join(valid_transitions))
            return action_result.set_status(phantom.APP_ERROR, message)

        try:
            transition_id = transition_info[0]['id']
        except:
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse response from server while trying to get information about status values")

        kwargs.update({'transition': transition_id})

        resolution_to_set = param.get(JIRA_JSON_RESOLUTION)

        if (resolution_to_set):

            # get the list of resolutions that we can set to
            resolutions = self._jira.resolutions()

            try:
                resolution_info = [x for x in resolutions if x.name == resolution_to_set]
            except:
                return action_result.set_status(phantom.APP_ERROR, "Unable to parse response from server while trying to get resolution about status values")

            if (not resolution_info):
                message = JIRA_ERR_ISSUE_VALID_RESOLUTION
                valid_resolutions = self._get_list_string(resolutions)
                if (valid_resolutions):
                    message = "{0} Valid resolution value(s): {1}".format(message, ', '.join(valid_resolutions))
                return action_result.set_status(phantom.APP_ERROR, message)

            try:
                resolution_id = resolution_info[0].id
            except:
                return action_result.set_status(phantom.APP_ERROR, "Unable to parse response from server while trying to get information about resolution values")

            if (resolution_to_set):
                kwargs.update({'fields': {'resolution': {'id': resolution_id}}})

        # So far, so good, try to now set the values
        try:
            self._jira.transition_issue(**kwargs)
        except Exception as e:
            message = "Unable to set ticket status"
            if (transition_id and resolution_to_set):
                # This period at the start is an intentional change for getting the error message in correct format
                message += ". The combination of status and resolution could be invalid"
            return self._set_jira_error(action_result, message, e)

        comment = param.get(JIRA_JSON_COMMENT)

        # to add comment to the issue if present
        comment_failure_msg = ""
        if comment:
            ret_val = self._add_comment_for_set_status(issue_id, issue, comment, action_result)

            # The on-premise Jira gives error when we try to add comment after closing the ticket.
            # Hence, not failing it but adding the message to the action_result
            if (phantom.is_fail(ret_val)):
                self.debug_print("Error occurred while adding the comment. Error message: {0}".format(action_result.get_message()))
                comment_failure_msg = JIRA_ERR_COMMENT_SET_STATUS_FAIL

        self.save_progress("Re-querying the ticket")
        ret_val = self._set_issue_data(issue_id, action_result)

        if (phantom.is_fail(ret_val)):
            error_message = action_result.get_message()
            if not error_message:
                error_message = ""

            if JIRA_ERR_FETCH_CUSTOM_FIELDS not in error_message:
                return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS,
                                        "The status is updated successfully" + (". NOTE: {0}".format(comment_failure_msg) if comment_failure_msg else ""))

    def _get_list_string(self, obj_list):

        # ret_string = ''
        ret_list = list()

        for item in obj_list:

            name = ''

            if (hasattr(item, 'raw')):
                name = item.name
            else:
                name = item.get('name')

            if (name):
                # ret_string += "<li>{0}</li>".format(name)
                ret_list.append(name)

        # if (ret_string):
            # ret_string = "<ul>{0}</ul>".format(ret_string)

        # return ret_string
        return ret_list

    def _update_ticket(self, param):

        # Progress
        self.save_progress(JIRA_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Create the jira object
        if (phantom.is_fail(self._create_jira_object())):
            return self.get_status()

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        issue_id = param[JIRA_JSON_ID]

        attachment = param.get(JIRA_JSON_ATTACHMENT)

        if ((not attachment) and (not param.get(JIRA_JSON_UPDATE_FIELDS))):
            return action_result.set_status(phantom.APP_ERROR, JIRA_ERR_UPDATE_NO_PARAM)

        try:
            issue = self._jira.issue(issue_id)
        except Exception as e:
            return self._set_jira_error(action_result, "Unable to find ticket info. Please make sure the issue exists", e)

        if (not issue):
            return action_result.set_status(phantom.APP_ERROR, "Unable to find ticket info. Please make sure the issue exists.")

        update_result = True

        if param.get(JIRA_JSON_UPDATE_FIELDS):

            update_result, update_fields = self._get_update_fields(param, issue_id, action_result)

            if phantom.is_fail(update_result):
                error_message = action_result.get_message()
                if not error_message:
                    error_message = ""

                if JIRA_ERR_FETCH_CUSTOM_FIELDS not in error_message:
                    return action_result.get_status()

            if (update_fields):
                update_result = self._add_update_fields(issue, update_fields, action_result)

        attach_result = True
        attachment_status = self._add_attachment(issue, attachment)

        if (attachment_status):

            if (action_result.get_message()):
                action_result.set_status(phantom.APP_ERROR)
                action_result.append_to_message(attachment_status)

            else:
                action_result.set_status(phantom.APP_ERROR, attachment_status)

            attach_result = False

        self.save_progress("Re-querying the ticket")

        ret_val = phantom.APP_SUCCESS

        error_message = ""
        if attach_result and update_result:
            ret_val = self._set_issue_data(issue_id, action_result)
            error_message = action_result.get_message()

        if not error_message:
            error_message = ""

        if (not ret_val and JIRA_ERR_FETCH_CUSTOM_FIELDS not in error_message) or not attach_result or not update_result:
            return action_result.set_status(phantom.APP_ERROR, 'Error occurred while updating the ticket. Error message: {0}'.format(action_result.get_message()))

        return action_result.set_status(phantom.APP_SUCCESS, JIRA_SUCC_TICKET_UPDATED)

    def _delete_ticket(self, param):

        # Progress
        self.save_progress(JIRA_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Create the jira object
        if (phantom.is_fail(self._create_jira_object())):
            return self.get_status()

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        issue_id = param[JIRA_JSON_ID]

        try:
            issue = self._jira.issue(issue_id)
        except Exception as e:
            return self._set_jira_error(action_result, "Unable to find ticket info. Please make sure the issue exists", e)

        if (not issue):
            return action_result.set_status(phantom.APP_ERROR, "Unable to find ticket info. Please make sure the issue exists.")

        self.save_progress("Deleting the ticket")

        try:
            issue.delete()
        except Exception as e:
            return self._set_jira_error(action_result, "Unable to delete the ticket", e)

        return action_result.set_status(phantom.APP_SUCCESS, JIRA_SUCC_TICKET_DELETED)

    def _create_ticket(self, param):

        # Progress
        self.save_progress(JIRA_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Create the jira object
        if (phantom.is_fail(self._create_jira_object())):
            return self.get_status()

        action_result = self.add_action_result(phantom.ActionResult(param))

        # get all the params for the issue
        project_key = param[JIRA_JSON_PROJECT_KEY]
        summary = param[JIRA_JSON_SUMMARY]
        issue_type = param[JIRA_JSON_ISSUE_TYPE]
        description = param.get(JIRA_JSON_DESCRIPTION)
        priority = param.get(JIRA_JSON_ISSUE_PRIORITY)
        assignee = param.get(JIRA_JSON_ISSUE_ASSIGNEE)
        attachment = param.get(JIRA_JSON_ATTACHMENT)

        fields = {}

        if param.get(JIRA_JSON_FIELDS):
            try:
                fields = json.loads(param.get(JIRA_JSON_FIELDS))
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR,
                            '{0}. Error: {1}'.format(JIRA_ERR_FIELDS_JSON_PARSE.format(field_name=JIRA_JSON_FIELDS), str(e).replace('{', '(').replace('}', ')')))

            if ('fields' in fields):
                if (len(fields.keys()) > 1):
                    return action_result.set_status(phantom.APP_ERROR, JIRA_ERR_INPUT_FIELDS_NOT_THE_ONLY_ONE)
                fields = fields['fields']

        # update value in fields if not present in the json
        if (project_key and ('project' not in fields)):
            fields['project'] = {}
            fields['project']['key'] = project_key

        if (summary and ('summary' not in fields)):
            fields['summary'] = summary

        if (description and ('description' not in fields)):
            fields['description'] = description

        if (issue_type and ('issuetype' not in fields)):
            fields['issuetype'] = {}
            fields['issuetype']['name'] = issue_type

        if (priority and ('priority' not in fields)):
            fields['priority'] = {}
            fields['priority']['name'] = priority

        self.save_progress("Creating the ticket")
        # Create JIRA ticket
        try:
            new_issue = self._jira.create_issue(fields=fields)
        except KeyError as ke:
            return action_result.set_status(phantom.APP_ERROR, "{0}. Missing required key: {1}".format(JIRA_ERR_CREATE_TICKET_FAILED, ke.message))
        except Exception as e:
            return self._set_jira_error(action_result, JIRA_ERR_CREATE_TICKET_FAILED, e)

        self.save_progress(JIRA_CREATED_TICKET)

        self.save_progress("Adding the attachment")
        attachment_status = self._add_attachment(new_issue, attachment)

        assignee_status = ""
        # now try to assign if required
        if (assignee is not None):
            self.save_progress("Assigning to user")
            try:
                self._jira.assign_issue(new_issue, assignee)
            except Exception as e:
                self.debug_print("Exception for assignee")
                assignee_status = JIRA_ERR_TICKET_ASSIGNMENT_FAILED.format(assignee, str(e))

        issue_id = new_issue.key

        self.save_progress("Re-querying the ticket")

        ret_val = self._set_issue_data(issue_id, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.set_status(phantom.APP_SUCCESS, JIRA_SUCC_TICKET_CREATED.format(id=new_issue.id, key=new_issue.key))

        result_data = action_result.get_data()[0]

        if (assignee_status):
            action_result.append_to_message(assignee_status)
            result_data['assign_error'] = assignee_status

        if (attachment_status):
            action_result.append_to_message(attachment_status)
            result_data['attach_error'] = attachment_status

        return action_result.get_status()

    def _list_tickets(self, param):

        # Progress
        self.save_progress(JIRA_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Create the jira object
        if (phantom.is_fail(self._create_jira_object())):
            return self.get_status()

        action_result = self.add_action_result(phantom.ActionResult(param))

        # get all the params for the search issue
        project_key = param[JIRA_JSON_PROJECT_KEY]
        query = "project={0}".format(project_key)

        action_query = param.get(JIRA_JSON_QUERY, "")
        start_index = param.get(JIRA_JSON_START_INDEX, DEFAULT_START_INDEX)
        limit = param.get(JIRA_JSON_MAX_RESULTS)

        if limit == 0 or (limit and (not str(limit).isdigit() or limit <= 0)):
            return action_result.set_status(phantom.APP_ERROR, JIRA_INVALID_LIMIT)

        if limit:
            limit = int(limit)

        if start_index < 0:
            return action_result.set_status(phantom.APP_ERROR, JIRA_ERR_NEGATIVE_INPUT)

        if (len(action_query) > 0):
            query = "{0} and {1}".format(query, action_query)

        issues = self._paginator(query, action_result, start_index=start_index, limit=limit)

        if issues is None:
            return action_result.get_status()

        for issue in issues:
            issue_ar = phantom.ActionResult()

            ret_val = self._parse_issue_data(issue, issue_ar)

            if phantom.is_fail(ret_val):
                self.debug_print('Error occurred while parsing the issue data: {0}. Error: {1}'.format(issue.key, issue_ar.get_message()))

            data = issue_ar.get_data()
            action_result.update_data(data)

        summary = action_result.update_summary({})
        summary[JIRA_TOTAL_ISSUES] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _add_comment_for_set_status(self, issue_id, issue, comment, action_result):
        ''' This method is used to add comment when we add comment while set status action.

        :rtype: string
        :param issue_id: Issue ID
        :param issue: Deatils of Issue
        :param comment: actual comment to be set
        :param action_result: action_result
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        '''
        if (phantom.is_fail(self._create_jira_object())):
            return self.get_status()

        update_body = {"update": {"comment": [{"add": {}}]}}
        comment_body = update_body['update']['comment'][0]['add']
        comment_body['body'] = comment

        ret_val, update_fields = self._get_update_fields({"update_fields": json.dumps(update_body)}, issue_id, action_result)

        error_message = action_result.get_message()
        if not error_message:
            error_message = ""

        if (not ret_val and JIRA_ERR_FETCH_CUSTOM_FIELDS not in error_message):
            return phantom.APP_ERROR

        if (not self._add_update_fields(issue, update_fields, action_result)):
            return phantom.APP_ERROR

        return action_result.set_status(phantom.APP_SUCCESS)

    def _add_comment(self, param):

        # Progress
        self.save_progress(JIRA_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Create the jira object
        if (phantom.is_fail(self._create_jira_object())):
            return self.get_status()

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        update_body = {"update": {"comment": [{"add": {}}]}}
        comment_body = update_body['update']['comment'][0]['add']

        issue_id = param[JIRA_JSON_ID]

        comment_body['body'] = param[JIRA_JSON_COMMENT]

        try:
            issue = self._jira.issue(issue_id)
        except Exception as e:
            return self._set_jira_error(action_result, "Unable to find ticket info. Please make sure the issue exists", e)

        if (not issue):
            return action_result.set_status(phantom.APP_ERROR, "Unable to find ticket info. Please make sure the issue exists.")

        ret_val, update_fields = self._get_update_fields({"update_fields": json.dumps(update_body)}, issue_id, action_result)

        error_message = action_result.get_message()
        if not error_message:
            error_message = ""

        if (not ret_val and JIRA_ERR_FETCH_CUSTOM_FIELDS not in error_message):
            return phantom.APP_ERROR

        if (not self._add_update_fields(issue, update_fields, action_result)):
            return phantom.APP_ERROR

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully added the comment")

    def _add_update_fields(self, issue, fields, action_result):

        if ('fields' in fields):
            self.save_progress("Modifying the ticket using the 'fields' dictionary")
            try:
                issue.update(fields=fields['fields'])
                del fields['fields']
            except Exception as e:
                return self._set_jira_error(action_result, JIRA_ERR_UPDATE_FAILED, e)

        if ('update' in fields):
            self.save_progress("Modifying the ticket with the 'update' dictionary")
            try:
                issue.update(update=fields['update'])
                del fields['update']
            except Exception as e:
                return self._set_jira_error(action_result, JIRA_ERR_UPDATE_FAILED, e)

        if (fields):
            # There are still some keys present so update the issue some more
            self.save_progress("Modifying the ticket with the input dictionary")
            try:
                issue.update(fields)
            except Exception as e:
                return self._set_jira_error(action_result, JIRA_ERR_UPDATE_FAILED, e)

        return phantom.APP_SUCCESS

    def _add_attachment(self, issue, vault_id):

        if (not vault_id):
            return ""

        self.save_progress("Adding attachment to ticket")

        # Check for file in vault
        try:
            meta = Vault.get_file_info(vault_id)  # Vault IDs are unique

            if (not meta):
                self.debug_print("Error while attaching")
                return JIRA_ERR_FILE_NOT_IN_VAULT

        except:
            return JIRA_ERR_FILE_NOT_IN_VAULT

        meta = meta[0]

        # Attach file to ticket
        try:
            path = Vault.get_file_path(vault_id)
            with open(path, 'rb') as f:
                self._jira.add_attachment(issue=issue, attachment=f, filename=meta['name'])
        except Exception as e:
            self.debug_print("Error while attaching")
            return JIRA_ERR_ATTACH_FAILED.format(str(e))

        return ""

    def _parse_issue_data(self, issue, action_result):

        try:
            # get the issue dict
            data = {}
            data[JIRA_JSON_NAME] = issue.key
            data[JIRA_JSON_ID] = issue.id
            issue_dict = issue.raw

            if ('fields' in issue_dict):
                data['fields'] = issue_dict['fields']

            data = action_result.add_data(data)
        except:
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse the response containing issue details from the server")

        try:
            data[JIRA_JSON_PRIORITY] = issue.fields.priority.name
        except:
            pass

        try:
            data[JIRA_JSON_RESOLUTTION] = issue.fields.resolution.name
        except:
            data[JIRA_JSON_RESOLUTTION] = "Unresolved"

        try:
            data[JIRA_JSON_STATUS] = issue.fields.status.name
        except:
            pass

        try:
            data[JIRA_JSON_REPORTER] = issue.fields.reporter.displayName
        except:
            pass

        try:
            data[JIRA_JSON_PROJECT_KEY] = issue.fields.project.key
        except:
            pass

        try:
            data[JIRA_JSON_SUMMARY] = issue.fields.summary
        except:
            pass

        try:
            data[JIRA_JSON_DESCRIPTION] = issue.fields.description
        except:
            pass

        try:
            data[JIRA_JSON_ISSUE_TYPE] = issue.fields.issuetype.name
        except:
            pass

        if (not data.get('fields')):
            # No fields, so nothing more to do, we've already added the data
            return phantom.APP_SUCCESS

        custom_fields_by_name = self._fetch_fields_by_replacing_custom_fields_id_to_name(issue, action_result)

        if custom_fields_by_name is None:
            return phantom.APP_ERROR

        return phantom.APP_SUCCESS

    def _set_issue_data(self, issue_id, action_result):

        try:
            issue = self._jira.issue(issue_id)
        except Exception as e:
            return self._set_jira_error(action_result, JIRA_ERR_GET_TICKET, e)

        return self._parse_issue_data(issue, action_result)

    def _get_ticket(self, param):

        # Progress
        self.save_progress(JIRA_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Create the jira object
        if (phantom.is_fail(self._create_jira_object())):
            return self.get_status()

        action_result = self.add_action_result(phantom.ActionResult(param))

        issue_id = param[JIRA_JSON_ID]

        ret_val = self._set_issue_data(issue_id, action_result)

        if (phantom.is_fail(ret_val)):
            error_message = action_result.get_message()
            if not error_message:
                error_message = ""

            if JIRA_ERR_FETCH_CUSTOM_FIELDS not in error_message:
                return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "The ticket has been retrieved successfully")

    def _get_container_id(self, issue_key):

        url = '{0}rest/container?_filter_source_data_identifier="{1}"&_filter_asset={2}'.format(self.get_phantom_base_url(), issue_key, self.get_asset_id())

        try:
            r = requests.get(url, verify=False)
            resp_json = r.json()
        except Exception as e:
            self.debug_print("Unable to query JIRA ticket container: ", e)
            return None

        if (resp_json.get('count', 0) <= 0):
            self.debug_print("No container matched")
            return None

        try:
            container_id = resp_json.get('data', [])[0]['id']
        except Exception as e:
            self.debug_print("Container results are not proper: ", e)
            return None

        return container_id

    def _get_artifact_id(self, sdi, container_id, issue_type="issue", full_artifact=False):

        url = '{0}rest/artifact?_filter_source_data_identifier="{1}"&_filter_container_id={2}&_filter_label="{3}"&sort=id&order=desc'.format(
                        self.get_phantom_base_url(), sdi, container_id, issue_type.lower())

        try:
            r = requests.get(url, verify=False)
            resp_json = r.json()
        except Exception as e:
            self.debug_print("Unable to query JIRA artifact: ", e)
            return None

        if (resp_json.get('count', 0) <= 0):
            self.debug_print("No artifact matched")
            return None

        try:
            if full_artifact:
                previous_artifacts_list = resp_json.get('data', [])
                return previous_artifacts_list[0]
            else:
                return resp_json.get('data', [])[0]['id']
        except Exception as e:
            self.debug_print("Artifact results are not proper: ", e)
            return None

    def _get_custom_fields_id_name_map(self, issue_id, action_result, id_to_name=True):

        custom_fields_id_name_map = dict()

        # get custom fields info
        ret_val, custom_fields_info, fields_meta = self._get_custom_fields_for_issue(issue_id, action_result)

        # Can't replace the custom fields, but the data has been set so the user can continue
        if (phantom.is_fail(ret_val)):
            message = action_result.get_message()
            action_result.set_status(phantom.APP_ERROR, "{0}. Error message: {1}".format(JIRA_ERR_FETCH_CUSTOM_FIELDS, message))
            return None

        if not custom_fields_info:
            return custom_fields_id_name_map

        if id_to_name:
            return dict([(x, fields_meta[x]['name']) for x in custom_fields_info])
        else:
            return dict([(fields_meta[x]['name'], x) for x in custom_fields_info])

    def _fetch_fields_by_replacing_custom_fields_id_to_name(self, issue, action_result):

        custom_id_to_name = self._get_custom_fields_id_name_map(issue.key, action_result)

        try:
            issue_dict = issue.raw
            fields = issue_dict.get('fields')
        except:
            action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching the fields from the issue: {0}".format(issue.key))
            return None

        if not custom_id_to_name:
            return fields

        ret_val, fields, _ = self._replace_custom_id_with_name(fields, custom_id_to_name, action_result)

        if phantom.is_fail(ret_val):
            return None

        return fields

    def _build_fields_artifact(self, issue, container_id, action_result):

        artifact_json = {}

        artifact_json['container_id'] = container_id
        artifact_json['source_data_identifier'] = issue.key

        try:
            artifact_json['label'] = issue.fields.issuetype.name
        except:
            artifact_json['label'] = "issue"

        artifact_cef = {}

        try:
            artifact_cef[JIRA_JSON_UPDATED_AT] = issue.fields.updated
        except:
            pass

        try:
            artifact_cef[JIRA_JSON_PRIORITY] = issue.fields.priority.name
        except:
            pass

        try:
            artifact_cef[JIRA_JSON_RESOLUTTION] = issue.fields.resolution.name
        except:
            artifact_cef[JIRA_JSON_RESOLUTTION] = JIRA_JSON_UNRESOLVED

        try:
            artifact_cef[JIRA_JSON_STATUS] = issue.fields.status.name
        except:
            pass

        try:
            artifact_cef[JIRA_JSON_REPORTER] = issue.fields.reporter.displayName
        except:
            pass

        try:
            artifact_cef[JIRA_JSON_PROJECT_KEY] = issue.fields.project.key
        except:
            pass

        try:
            artifact_cef[JIRA_JSON_SUMMARY] = issue.fields.summary
        except:
            pass

        try:
            artifact_cef[JIRA_JSON_DESCRIPTION] = issue.fields.description
        except:
            pass

        try:
            artifact_cef[JIRA_JSON_ISSUE_TYPE] = issue.fields.issuetype.name
        except:
            pass

        config = self.get_config()
        custom_fields = config.get(JIRA_JSON_CUSTOM_FIELDS)

        if custom_fields:

            custom_fields_list = [x.strip() for x in custom_fields.split(',')]
            custom_fields_list = list(filter(None, custom_fields_list))

            custom_fields_by_name = self._fetch_fields_by_replacing_custom_fields_id_to_name(issue, action_result)

            if custom_fields_by_name is None:
                return None

            for custom_field in custom_fields_list:
                try:
                    artifact_cef[custom_field] = custom_fields_by_name[custom_field]
                except:
                    pass

        artifact_json['cef'] = artifact_cef

        return artifact_json

    def _download_file(self, url, local_file_path):

        self.debug_print("Downloading from: ", url)

        config = self.get_config()
        auth = (config[phantom.APP_JSON_USERNAME], config[phantom.APP_JSON_PASSWORD])

        try:
            r = requests.get(url, verify=self.get_config().get("verify_server_cert"), stream=True, auth=auth)
        except Exception as e:
            self.debug_print("Could not connect to url to download attachment: ", e)
            return phantom.APP_ERROR

        if not r:
            # GET failed
            self.debug_print("Error downloading file. Server returned with status code: {0}".format(r.status_code))
            return phantom.APP_ERROR

        bytes_downloaded = 0
        block_size = 512 * 1024

        try:
            with open(local_file_path, 'wb') as file_handle:
                for chunk in r.iter_content(chunk_size=block_size):
                    if (chunk):
                        bytes_downloaded += len(chunk)
                        file_handle.write(chunk)
                        file_handle.flush()
                        os.fsync(file_handle.fileno())
                        self.send_progress("Downloaded {0} bytes".format(bytes_downloaded))
        except Exception as e:
            self.debug_print("Error downloading file: ", e)
            return phantom.APP_ERROR

        os.chmod(local_file_path, 0o660)

        return phantom.APP_SUCCESS

    def _handle_attachment(self, attachment, container_id, artifact_list, action_result):

        if hasattr(Vault, 'get_vault_tmp_dir'):
            tmp = tempfile.NamedTemporaryFile(dir=Vault.get_vault_tmp_dir(), delete=False)
        else:
            tmp = tempfile.NamedTemporaryFile(dir='/opt/phantom/vault/tmp/', delete=False)

        ret_val = self._download_file(attachment.content, tmp.name)

        if (phantom.is_fail(ret_val)):
            return phantom.APP_ERROR

        vault_ret = Vault.add_attachment(tmp.name, container_id, attachment.filename)

        if not vault_ret.get('succeeded'):
            self.debug_print("Error saving file to vault: ", vault_ret.get('message', "Could not save file to vault"))
            return phantom.APP_ERROR

        artifact_json = {}

        artifact_json['name'] = 'attachment - {0}'.format(attachment.filename)
        artifact_json['label'] = 'attachment'
        artifact_json['container_id'] = container_id
        artifact_json['source_data_identifier'] = attachment.id

        artifact_cef = {}

        artifact_cef['size'] = attachment.size
        artifact_cef['created'] = attachment.created
        artifact_cef['filename'] = attachment.filename
        artifact_cef['mimeType'] = attachment.mimeType
        artifact_cef['author'] = attachment.author.name
        artifact_cef['vault_id'] = vault_ret[phantom.APP_JSON_HASH]

        artifact_json['cef'] = artifact_cef

        artifact_list.append(artifact_json)

        return phantom.APP_SUCCESS

    def _handle_comment(self, comment, container_id, base_name, artifact_list, action_result):

        try:
            artifact_json = {}

            artifact_json['name'] = '{0} by {1}'.format(base_name, comment.author.name)
            artifact_json['label'] = 'comment'
            artifact_json['container_id'] = container_id
            artifact_json['source_data_identifier'] = comment.id

            artifact_cef = {}

            artifact_cef['body'] = comment.body
            artifact_cef['created'] = comment.created
            artifact_cef['updated'] = comment.updated
            artifact_cef['author'] = comment.author.name
            artifact_cef['updateAuthor'] = comment.updateAuthor.name

            artifact_json['cef'] = artifact_cef

            artifact_list.append(artifact_json)
        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, "Error occurred while creation of the comment artifact. Error message: {0}".format(str(e)))
            return phantom.APP_ERROR

        return phantom.APP_SUCCESS

    def _paginator(self, jql_query, action_result, start_index=0, limit=None, fields=False):

        issues_list = list()

        while True:
            try:
                if fields:
                    issues = self._jira.search_issues(jql_str=jql_query, startAt=start_index, maxResults=DEFAULT_MAX_RESULTS, fields='updated')
                else:
                    issues = self._jira.search_issues(jql_str=jql_query, startAt=start_index, maxResults=DEFAULT_MAX_RESULTS)
            except Exception as e:
                action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching the list of tickets (issues). Error: {0}".format(str(e)))
                return None

            if issues is None:
                action_result.set_status(phantom.APP_ERROR, 'Unknown error occurred while fetching list of tickets (issues) using pagination.')
                return None

            issues_list.extend(issues)

            if limit and len(issues_list) >= limit:
                return issues_list[:limit]

            if len(issues) < DEFAULT_MAX_RESULTS:
                break

            start_index = start_index + DEFAULT_MAX_RESULTS

        return issues_list

    def _handle_link_tickets(self, param):

        # Progress
        self.save_progress(JIRA_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Create the jira object
        if (phantom.is_fail(self._create_jira_object())):
            return self.get_status()

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        from_issue = param[JIRA_JSON_FROM_ID]
        to_issue = param[JIRA_JSON_TO_ID]
        link_type = param[JIRA_JSON_LINK_TYPE]
        comment_body = param.get(JIRA_JSON_COMMENT)
        comment_vis_type = param.get(JIRA_JSON_COMMENT_VISIBILITY_TYPE)
        comment_vis_value = param.get(JIRA_JSON_COMMENT_VISIBILITY)
        comment = None

        try:
            link_type.encode('utf-8')
        except:
            return action_result.set_status(phantom.APP_ERROR, "Parameter value failed validation. Enter a valid value.")

        if comment_body:
            comment = {
                "body": comment_body,
                "visibility": {
                    "type": comment_vis_type,
                    "value": comment_vis_value
                }
            }

        try:
            link = self._jira.create_issue_link(link_type, from_issue, to_issue, comment)
            self.save_progress("Response from server:{}".format(link))
        except Exception as e:
            return self._set_jira_error(action_result, "Failed to link the issues", e)

        action_result.add_data({"result": "success"})

        return action_result.set_status(phantom.APP_SUCCESS, "The ticket has been linked successfully")

    def _handle_add_watcher(self, param):

        self.save_progress(JIRA_USING_BASE_URL, base_url=self._base_url)
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Create the jira object
        if (phantom.is_fail(self._create_jira_object())):
            return self.get_status()

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        issue_id = param[JIRA_JSON_ISSUE_ID]
        username = param[JIRA_JSON_WATCHER]

        ret_val, watchers = self.get_watchers_list(action_result, issue_id)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if username.lower() in watchers:
            return action_result.set_status(phantom.APP_ERROR, "The given username already exists in the watchers list of the issue: {0}".format(issue_id))

        try:
            self._jira.add_watcher(issue_id, username)
        except Exception as e:
            self.save_progress("Response from the server: {0}".format(str(e)))
            return action_result.set_status(phantom.APP_ERROR, "Failed to add the watcher. Please check the provided parameters.")

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully added the user to the watchers list of the issue ID: {0}".format(issue_id))

    def get_watchers_list(self, action_result, issue_id):

        try:
            response = self._jira.watchers(issue_id)
        except Exception as e:
            self.save_progress("Response from the server:{}".format(str(e)))
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching the watchers list. Error: {0}".format(str(e))), None

        watcher_list = list()
        for watcher in response.watchers:
            watcher_list.append(str(watcher.name))

        return phantom.APP_SUCCESS, list(map(str.lower, watcher_list))

    def _handle_remove_watcher(self, param):

        self.save_progress(JIRA_USING_BASE_URL, base_url=self._base_url)
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Create the jira object
        if (phantom.is_fail(self._create_jira_object())):
            return self.get_status()

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        issue_id = param[JIRA_JSON_ISSUE_ID]
        username = param[JIRA_JSON_WATCHER]

        ret_val, watchers = self.get_watchers_list(action_result, issue_id)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not watchers:
            return action_result.set_status(phantom.APP_ERROR, "No watchers found in the issue ID: {0}".format(issue_id))

        if username.lower() not in watchers:
            return action_result.set_status(phantom.APP_ERROR, "The given username is not found in the watchers list of the issue ID: {0}".format(issue_id))

        try:
            self._jira.remove_watcher(issue_id, username)
        except Exception as e:
            self.save_progress("Response from the server: {0}".format(str(e)))
            return action_result.set_status(phantom.APP_ERROR, "Failed to remove the watcher. Please check the provided parameters.")

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully removed the user from the watchers list of the issue ID: {0}".format(issue_id))

    def _check_to_create_updated_artifact(self, container_id, issue, previous_full_artifact, action_result):

        issue_details = []
        issue_details.append(container_id)

        try:
            issue_details.append(issue.key)
        except:
            issue_details.append(None)

        try:
            issue_details.append(issue.fields.issuetype.name.lower())
        except:
            issue_details.append(None)

        try:
            issue_details.append(issue.fields.priority.name)
        except:
            issue_details.append(None)

        try:
            issue_details.append(issue.fields.resolution.name)
        except:
            issue_details.append(JIRA_JSON_UNRESOLVED)

        try:
            issue_details.append(issue.fields.status.name)
        except:
            issue_details.append(None)

        try:
            issue_details.append(issue.fields.reporter.displayName)
        except:
            issue_details.append(None)

        try:
            issue_details.append(issue.fields.project.key)
        except:
            issue_details.append(None)

        try:
            issue_details.append(issue.fields.summary)
        except:
            issue_details.append(None)

        try:
            issue_details.append(issue.fields.description)
        except:
            issue_details.append(None)

        try:
            issue_details.append(issue.fields.issuetype.name)
        except:
            issue_details.append(None)

        artifact_details = []
        artifact_details.append(previous_full_artifact.get(JIRA_JSON_CONTAINER))
        artifact_details.append(previous_full_artifact.get(JIRA_JSON_SDI))
        artifact_details.append(previous_full_artifact.get(JIRA_JSON_LABEL))
        artifact_details.append(previous_full_artifact.get(JIRA_JSON_CEF, {}).get(JIRA_JSON_PRIORITY))
        artifact_details.append(previous_full_artifact.get(JIRA_JSON_CEF, {}).get(JIRA_JSON_RESOLUTTION))
        artifact_details.append(previous_full_artifact.get(JIRA_JSON_CEF, {}).get(JIRA_JSON_STATUS))
        artifact_details.append(previous_full_artifact.get(JIRA_JSON_CEF, {}).get(JIRA_JSON_REPORTER))
        artifact_details.append(previous_full_artifact.get(JIRA_JSON_CEF, {}).get(JIRA_JSON_PROJECT_KEY))
        artifact_details.append(previous_full_artifact.get(JIRA_JSON_CEF, {}).get(JIRA_JSON_SUMMARY))
        artifact_details.append(previous_full_artifact.get(JIRA_JSON_CEF, {}).get(JIRA_JSON_DESCRIPTION))
        artifact_details.append(previous_full_artifact.get(JIRA_JSON_CEF, {}).get(JIRA_JSON_ISSUE_TYPE))

        config = self.get_config()
        custom_fields = config.get(JIRA_JSON_CUSTOM_FIELDS)

        if custom_fields:

            custom_fields_list = [x.strip() for x in custom_fields.split(',')]
            custom_fields_list = list(filter(None, custom_fields_list))

            custom_fields_by_name = self._fetch_fields_by_replacing_custom_fields_id_to_name(issue, action_result)

            if custom_fields_by_name is None:
                return None

            for custom_field in custom_fields_list:
                issue_details.append(custom_fields_by_name.get(custom_field))
                artifact_details.append(previous_full_artifact.get(JIRA_JSON_CEF, {}).get(custom_field))

        if issue_details == artifact_details:
            return False
        else:
            return True

    def _update_container(self, issue, container_id, last_time, action_result):

        update_json = {}
        update_json['data'] = issue.raw
        update_json['description'] = issue.fields.summary

        url = '{0}rest/container/{1}'.format(self.get_phantom_base_url(), container_id)

        try:
            r = requests.post(url, data=json.dumps(update_json), verify=False)
            resp_json = r.json()
        except Exception as e:
            self.debug_print("Error while updating the container. Error is: ", e)
            action_result.set_status(phantom.APP_ERROR, "Error occurred while updating the container for the issue key: {0}. Error message: {1}".format(issue.key, str(e)))
            return phantom.APP_ERROR

        if r.status_code != 200 or resp_json.get('failed'):
            self.debug_print("Error while updating the container. Error is: ", resp_json.get('failed'))
            action_result.set_status(phantom.APP_ERROR,
                                "Error occurred while updating the container for the issue key: {0}. Error message: {1}".format(issue.key, resp_json.get('failed')))
            return phantom.APP_ERROR

        artifact_list = []

        try:
            for attachment in issue.fields.attachment:
                if not self._get_artifact_id(attachment.id, container_id):
                    ret_val = self._handle_attachment(attachment, container_id, artifact_list, action_result)

                    if phantom.is_fail(ret_val):
                        return phantom.APP_ERROR
        except:
            pass

        try:

            for comment in issue.fields.comment.comments:

                if not self._get_artifact_id(comment.id, container_id):
                    ret_val = self._handle_comment(comment, container_id, '{0}_{1}'.format('comment', comment.updated), artifact_list, action_result)

                    if phantom.is_fail(ret_val):
                        return phantom.APP_ERROR

                    continue

                update_time = issue.fields.updated[:-5]
                update_datetime = datetime.strptime(update_time, "%Y-%m-%dT%H:%M:%S.%f")
                update_epoch = (update_datetime - datetime.utcfromtimestamp(0)).total_seconds()

                if self.is_poll_now() or (update_epoch > last_time):
                    ret_val = self._handle_comment(comment, container_id, '{0}_{1}'.format('comment', comment.updated), artifact_list, action_result)

                    if phantom.is_fail(ret_val):
                        return phantom.APP_ERROR

        except:
            pass

        try:
            issue_type = issue.fields.issuetype.name
        except:
            issue_type = "issue"

        previous_full_artifact = self._get_artifact_id(issue.key, container_id, issue_type=issue_type, full_artifact=True)

        if not previous_full_artifact:
            return phantom.APP_ERROR

        to_create_updated_artifact = self._check_to_create_updated_artifact(container_id, issue, previous_full_artifact, action_result)

        if to_create_updated_artifact is None:
            return phantom.APP_ERROR

        if to_create_updated_artifact:
            artifact_json = self._build_fields_artifact(issue, container_id, action_result)

            if artifact_json is None:
                return phantom.APP_ERROR

            artifact_json['name'] = '{0}_{1}'.format('ticket fields', issue.fields.updated)

            artifact_list.append(artifact_json)

        if artifact_list:
            ret_val, message, resp = self.save_artifacts(artifact_list)

            if (not ret_val):
                self.debug_print("Error saving the artifact: ", message)
                action_result.set_status(phantom.APP_ERROR, "Error occurred while saving the artifact. Error message: {0}", message)
                return phantom.APP_ERROR

        return phantom.APP_SUCCESS

    def _save_issue(self, issue, last_time, action_result):

        container_id = self._get_container_id(issue.key)

        if container_id:
            # Ticket has already been ingested. Need to update its container.
            ret_val = self._update_container(issue, container_id, last_time, action_result)

            if phantom.is_fail(ret_val):
                return phantom.APP_ERROR

            return phantom.APP_SUCCESS

        # Build the container JSON
        container_json = {}
        container_json['name'] = issue.key
        container_json['data'] = issue.raw
        container_json['description'] = issue.fields.summary
        container_json['source_data_identifier'] = issue.key
        container_json['label'] = self.get_config().get('ingest', {}).get('container_label')

        # Save the container
        ret_val, message, container_id = self.save_container(container_json)

        if not ret_val:
            return phantom.APP_ERROR

        artifact_list = []

        # Check for and save attachments as artifacts
        try:
            for attachment in issue.fields.attachment:
                ret_val = self._handle_attachment(attachment, container_id, artifact_list, action_result)

                if phantom.is_fail(ret_val):
                    return phantom.APP_ERROR
        except:
            pass

        # Check for and save comments as artifacts
        try:
            for comment in issue.fields.comment.comments:
                ret_val = self._handle_comment(comment, container_id, '{0}_{1}'.format('comment', comment.updated), artifact_list, action_result)

                if phantom.is_fail(ret_val):
                    return phantom.APP_ERROR
        except:
            pass

        # Create the main artifact of the container that will hold the ticket's fields
        artifact_json = self._build_fields_artifact(issue, container_id, action_result)

        if artifact_json is None:
            return phantom.APP_ERROR

        artifact_json['name'] = '{0}_{1}'.format('ticket fields', issue.fields.updated)

        artifact_list.append(artifact_json)

        ret_val, message, resp = self.save_artifacts(artifact_list)

        if not ret_val:
            return phantom.APP_ERROR

        return phantom.APP_SUCCESS

    def _on_poll(self, param):

        # Progress
        self.save_progress(JIRA_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Create the jira object
        if (phantom.is_fail(self._create_jira_object())):
            return self.get_status()

        # Check for load_state API, use it if it is present
        if (hasattr(self, 'load_state')):
            state = self.load_state()
        else:
            state = self._load_state()

        # Get config
        config = self.get_config()

        # Add action result
        action_result = self.add_action_result(phantom.ActionResult(param))

        # Get time from last poll, save now as time for this poll
        last_time = state.get('last_time', 0)

        if last_time:
            try:
                # Shifting the last_time by one minute to ensure that
                # the tickets are not missed in the On Poll due to
                # a minute's granularity of the Jira
                last_time = int(last_time)
                last_time = last_time - 60

                if last_time < 0:
                    last_time = 0

            except:
                return action_result.set_status(phantom.APP_ERROR,
                                                "Error occurred while parsing the last ingested ticket's (issue's) 'updated' timestamp from the previous ingestion run")

        # Build the query for the issue search
        query = ""

        project_key = config.get(JIRA_JSON_PROJECT_KEY)
        if project_key:
            query = "project={0}".format(project_key)

        action_query = config.get(JIRA_JSON_QUERY, "")

        if (len(action_query) > 0):
            query = "{0}{1}{2}".format(query, ' and ' if query else '', action_query)

        # If it's a poll now don't filter based on update time
        if self.is_poll_now():
            max_tickets = param.get(phantom.APP_JSON_CONTAINER_COUNT)

        # If it's the first poll, don't filter based on update time
        elif (state.get('first_run', True)):
            state['first_run'] = False
            max_tickets = int(config.get('first_run_max_tickets', -1))

        # If it's scheduled polling add a filter for update time being greater than the last poll time
        else:
            max_tickets = int(config.get('max_tickets', -1))
            query = '{0}{1}updated>="{2}"'.format(query, ' and ' if query else '', datetime.fromtimestamp(last_time).strftime(JIRA_TIME_FORMAT))

        # Order by update time
        query = "{0} order by updated asc".format(query if query else '')

        # Query for issues
        issues = self._paginator(query, action_result, limit=max_tickets, fields=True)

        if issues is None:
            return action_result.get_status()

        # Ingest the issues
        failed = 0
        for issue in issues:
            if (not self._save_issue(self._jira.issue(issue.key), last_time, action_result)):
                failed += 1

        if not self.is_poll_now() and issues:
            last_fetched_issue = self._jira.issue(issues[-1].key)
            last_fetched_issue_updated_timestamp = time.mktime(datetime.strptime(last_fetched_issue.fields.updated[:-5], "%Y-%m-%dT%H:%M:%S.%f").timetuple())
            state['last_time'] = last_fetched_issue_updated_timestamp

        # Check for save_state API, use it if it is present
        if (hasattr(self, 'save_state')):
            self.save_state(state)
        else:
            self._save_state(state)

        if (failed):
            return action_result.set_status(phantom.APP_ERROR, JIRA_ERR_FAILURES)

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
        elif (action == self.ACTION_ID_LIST_PROJECTS):
            ret_val = self._list_projects(param)
        elif (action == self.ACTION_ID_LIST_TICKETS):
            ret_val = self._list_tickets(param)
        elif (action == self.ACTION_ID_GET_TICKET):
            ret_val = self._get_ticket(param)
        elif (action == self.ACTION_ID_UPDATE_TICKET):
            ret_val = self._update_ticket(param)
        elif (action == self.ACTION_ID_DELETE_TICKET):
            ret_val = self._delete_ticket(param)
        elif (action == self.ACTION_ID_SET_TICKET_STATUS):
            ret_val = self._set_ticket_status(param)
        elif (action == self.ACTION_ID_ADD_COMMENT):
            ret_val = self._add_comment(param)
        elif (action == self.ACTION_ID_LINK_TICKETS):
            ret_val = self._handle_link_tickets(param)
        elif (action == self.ACTION_ID_ADD_WATCHER):
            ret_val = self._handle_add_watcher(param)
        elif (action == self.ACTION_ID_REMOVE_WATCHER):
            ret_val = self._handle_remove_watcher(param)
        elif (action == self.ACTION_ID_ON_POLL):
            ret_val = self._on_poll(param)
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
            r = requests.get(phantom.BaseConnector._get_phantom_base_url() + "login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = phantom.BaseConnector._get_phantom_base_url() + 'login'

            print("Logging into Platform to get the session id")
            r2 = requests.post(phantom.BaseConnector._get_phantom_base_url() + "login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = JiraConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
