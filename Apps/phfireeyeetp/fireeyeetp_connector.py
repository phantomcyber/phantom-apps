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
from phantom.vault import Vault

# Usage of the consts file is recommended
from fireeyeetp_consts import *
import requests
import json
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
import uuid
import os
import hashlib
import pytz
# import pudb


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class FireeyeEtpConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(FireeyeEtpConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

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

    def _process_file_response(self, r, action_result):
        # Try to parse the file data with the .content
        try:
            resp_json = r.content
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse response. Error: {0}".format(str(e))
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

        # Check to see if we are downloading a file.
        # Files are still showing a Content-Type of JSON althoug there is no JSON data.
        if r.headers.get('Content-Disposition'):
            return self._process_file_response(r, action_result)

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

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url,
                verify=config.get('verify_server_cert', False),
                headers=self._header,
                **kwargs
            )
            # print(r.text)
            # print(r.headers)
            # print(r.json)
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _save_file_to_vault(self, data, filename, container_id, action_result):
        # Creating temporary directory and file
        try:
            if hasattr(Vault, 'get_vault_tmp_dir'):
                temp_dir = Vault.get_vault_tmp_dir()
            else:
                temp_dir = "/opt/phantom/vault/tmp/"

            temp_dir = temp_dir + '/{}'.format(uuid.uuid4())

            os.makedirs(temp_dir)

            file_path = os.path.join(temp_dir, filename)

            with open(file_path, 'wb') as file_obj:
                file_obj.write(data)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error while writing to temporary file", e), None

        # Adding pcap to vault
        vault_ret_dict = Vault.add_attachment(file_path, container_id, filename)

        # Removing temporary directory created to download file
        try:
            os.rmdir(temp_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to remove temporary directory", e), None

        # Updating data with vault details
        if vault_ret_dict['succeeded']:
            vault_details = {
                phantom.APP_JSON_VAULT_ID: vault_ret_dict[phantom.APP_JSON_HASH],
                'file_name': filename
            }
            return phantom.APP_SUCCESS, vault_details

        # Error while adding report to vault
        self.debug_print('Error adding file to vault:', vault_ret_dict)
        action_result.append_to_message('. {}'.format(vault_ret_dict['message']))

        # Set the action_result status to error, the handler function will most probably return as is
        return phantom.APP_ERROR, None

    def _paginator(self, endpoint, action_result, data, method="get", **kwargs):

        items_list = list()

        limit = data['size']

        while True:
            ret_val, items = self._make_rest_call(action_result, endpoint, json=data, method=method, **kwargs)

            if phantom.is_fail(ret_val):
                return None

            items_list.extend(items.get('data').get('attributes'))

            print("Total count: {}   Size: {} ".format(items.get('meta').get('total'), limit))

            if limit and items.get('meta').get('total') >= limit:
                #return items_list[:limit]
                data['fromLastModifiedOn'] = items.get('meta').get('fromLastModifiedOn').get('end')

            if items.get('meta').get('total') < limit:
                break

        return items_list

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")

        data = {}

        data['size'] = 1

        endpoint = FIREETEETP_LIST_ALERTS_ENDPOINT

        # make rest call
        ret_val = self._make_rest_call(endpoint, action_result, method="post", data=data)

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_alerts(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # pudb.set_trace()

        data = {}

        # Check the limit paramter
        if param.get('size') > 200:
            size = 200
        elif param.get('size') > 0:
            size = param.get('size')

        data['size'] = size

        # Check the legacy id parameter
        if param.get('legacy_id') and data.get('attributes'):
            data['attributes']['legacy_id'] = param.get('legacy_id')
        else:
            data['attributes'] = {}
            data['attributes']['legacy_id'] = param.get('legacy_id')

        # Check the message id parameter
        if param.get('message_id') and data.get('attributes'):
            data['attributes']['etp_message_id'] = param.get('message_id')
        else:
            data['attributes'] = {}
            data['attributes']['etp_message_id'] = param.get('message_id')

        # Check the email status parmater
        if param.get('email_status') and data.get('attributes'):
            data['attributes']['email_status'] = ",".join(param.get('email_status'))
        else:
            data['attributes'] = {}
            data['attributes']['email_status'] = param.get('email_status')

        # Check and calculate the timestamp to filter by
        if param.get('num_days'):
            timestamp = datetime.today() - timedelta(days=param.get('num_days'))
            date = timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")
            data['fromLastModifiedOn'] = date

        endpoint = FIREETEETP_LIST_ALERTS_ENDPOINT

        # make rest call
        response = self._paginator(endpoint, action_result, data, method="post")

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_alert(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # pudb.set_trace()

        endpoint = FIREETEETP_GET_ALERT_ENDPOINT.format(alertId=param.get('alert_id'))

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result)

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

    def _handle_list_email_attributes(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # pudb.set_trace()

        data = {}

        # Check the limit paramter
        if param.get('size') > 200:
            size = 200
        elif param.get('size') > 0:
            size = param.get('size')

        data['size'] = size

        endpoint = FIREETEETP_LIST_MESSAGE_ATTRIBUTES_ENDPOINT

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, json=data, method="post")

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

    def _handle_get_email_attributes(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # pudb.set_trace()

        endpoint = FIREETEETP_GET_MESSAGE_ATTRIBUTES_ENDPOINT.format(etp_message_id=param.get('etp_message_id'))

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result)

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

    def _handle_trace_email(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # pudb.set_trace()

        params = {}

        if param.get("original_message_id"):
            params['original_message_id'] = param.get("original_message_id")

        if param.get("downstream_message_id"):
            params['downstream_message_id'] = param.get("downstream_message_id")

        params['size'] = params.get("size")

        endpoint = FIREETEETP_GET_MESSAGE_TRACE_ENDPOINT

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

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

    def _handle_get_email(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # pudb.set_trace()

        # Set the file name for the vault
        filename = "raw_email_{}.txt".format(param.get("etp_message_id"))

        endpoint = FIREETEETP_GET_EMAIL_ENDPOINT.format(etp_message_id=param.get("etp_message_id"))

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        ret_val, vault_details = self._save_file_to_vault(response, filename, self.get_container_id(), action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data, uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_pcap(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # pudb.set_trace()

        data = {}

        # Set the file name for the vault
        filename = "{}_pcap.zip".format(param.get("alert_id"))

        endpoint = FIREETEETP_GET_ALERT_PCAP_FILES_ENDPOINT.format(alertId=param.get("alert_id"))

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, method="post", json=data, stream=True)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        ret_val, vault_details = self._save_file_to_vault(response, filename, self.get_container_id(), action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data, uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_malware_files(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # pudb.set_trace()

        data = {}

        # Set the file name for the vault
        filename = "{}_malware.zip".format(param.get("alert_id"))

        endpoint = FIREETEETP_GET_ALERT_MALWARE_FILES_ENDPOINT.format(alertId=param.get("alert_id"))

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, method="post", json=data, stream=True)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        ret_val, vault_details = self._save_file_to_vault(response, filename, self.get_container_id(), action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data, uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_case_files(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # pudb.set_trace()

        data = {}

        # Set the file name for the vault
        filename = "{}_case.zip".format(param.get("alert_id"))

        endpoint = FIREETEETP_GET_ALERT_CASE_FILES_ENDPOINT.format(alertId=param.get("alert_id"))

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, method="post", json=data, stream=True)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        ret_val, vault_details = self._save_file_to_vault(response, filename, self.get_container_id(), action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data, uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_remediate_emails(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # pudb.set_trace()

        data = {}

        if param.get('action_override'):
            data['action_override'] = param.get('action_override')

            if not param.get('move_to'):
                action_result.set_status(phantom.APP_ERROR, "If the parameter action_override is enabled the move_to parameter also needs to be filled out.")
                return action_result.get_status()
            else:
                data['move_to'] = param.get('move_to')

        data['message_ids'] = ",".join(param.get('etp_message_ids'))

        endpoint = FIREETEETP_REMEDIATE_EMAILS_ENDPOINT

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, method="post", json=data)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data, uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_quarantined_email(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # pudb.set_trace()

        # Set the file name for the vault
        filename = "quarantined_email_{}.txt".format(param.get("etp_message_id"))

        endpoint = FIREEYEETP_GET_QUARANTINED_EMAIL_ENDPOINT.format(etp_message_id=param.get("etp_message_id"))

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        ret_val, vault_details = self._save_file_to_vault(response, filename, self.get_container_id(), action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data, uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unquarantine_email(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # pudb.set_trace()

        data = {}

        ids = param.get("etp_message_ids", None).split(',')

        if len(ids) > 1:
            data['message_ids'] = ",".join(param.get('etp_message_ids'))
            endpoint = FIREEYEETP_BULK_RELEASE_QUARANTINE_EMAILS_ENDPOINT
        else:
            endpoint = FIREEYEETP_RELEASE_QUARANTINED_EMAIL_ENDPOINT.format(etp_message_id=ids)

        if param.get("is_not_spam"):
            data['is_not_spam'] = param.get("is_not_spam")

        if param.get("headers_only"):
            data['headers_only'] = param.get("headers_only")

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, method="post", json=data)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data, uncomment code as you deem fit
        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_quarantined_email(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # pudb.set_trace()

        data = {}

        ids = param.get("etp_message_ids", None).split(',')

        if len(ids) > 1:
            data['message_ids'] = ",".join(param.get('etp_message_ids'))
            endpoint = FIREEYEETP_BULK_DELETE_QUARANTINE_EMAILS_ENDPOINT
        else:
            endpoint = FIREEYEETP_DELETE_QUARANTINED_EMAIL_ENDPOINT.format(etp_message_id=ids)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, method="post", json=data)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data, uncomment code as you deem fit
        # Add the response into the data section
        resp_data = response

        # Normalize output data so it matches for both actions.
        # The endpoint called when you are delete 1 specific email produces different output data
        if resp_data.get('data').get('deleted'):
            resp_data['data']['successful_message_ids'] = resp_data.get('data').get('message_ids')
            resp_data['data']['operation'] = "delete"
            resp_data['data']['failed_message_ids'] = []
            del resp_data['data']['message_ids']
            del resp_data['data']['deleted']
        else:
            resp_data['data']['failed_message_ids'] = resp_data.get('data').get('message_ids')
            resp_data['data']['operation'] = "delete"
            resp_data['data']['successful_message_ids'] = []
            del resp_data['data']['message_ids']
            del resp_data['data']['deleted']

        action_result.add_data(resp_data)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_quarantined_emails(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # pudb.set_trace()

        data = {}

        # Check the limit paramter
        if param.get('size') > 200:
            size = 200
        elif param.get('size') > 0:
            size = param.get('size')

        data['size'] = size

        endpoint = FIREEYEETP_LIST_QUARANTINED_EMAILS_ENDPOINT

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, json=data, method="post")

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

    def _handle_on_poll(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # pudb.set_trace()

        data = {}

        # Check the limit paramter
        if param.get('container_count') > 200:
            size = 200
        elif param.get('container_count') > 0:
            size = param.get('container_count')

        data['size'] = size

        # Check and calculate the timestamp to filter by
        if param.get('num_days'):
            timestamp = datetime.today() - timedelta(days=param.get('num_days'))
            date = timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")
            data['fromLastModifiedOn'] = date

        endpoint = FIREETEETP_LIST_ALERTS_ENDPOINT

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, data=data, method="post")

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

    def _convert_timestamp_to_string(self, timestamp, tz):
        """ This function is used to handle of timestamp converstion for on_poll action.
        :param timestamp: Epoch time stamp
        :param tz: Timezone configued in the Asset
        :return: datetime string
        """

        date_time = datetime.fromtimestamp(timestamp, pytz.timezone(tz))

        return date_time.strftime('%Y-%m-%dT%H:%M:%S:%fZ')

    def _create_container(self, alert):
        """ This function is used to create the container in Phantom using alert data.
        :param alert: Data of single alert
        :return: status(success/failure), container_id
        """
        container_dict = dict()

        container_dict['name'] = '{alert_name}'.format(alert_name=alert['data']['entires']['assessment'])
        container_dict['source_data_identifier'] = container_dict['name']
        container_dict['description'] = alert['data']['entires']['assessment']

        container_creation_status, container_creation_msg, container_id = self.save_container(container=container_dict)

        if phantom.is_fail(container_creation_status):
            self.debug_print(container_creation_msg)
            self.save_progress('Error while creating container for alert {alert_name}. '
                               '{error_message}'.format(alert_name=alert['data']['entires']['assessment'], error_message=container_creation_msg))
            return self.set_status(phantom.APP_ERROR)

        return self.set_status(phantom.APP_SUCCESS), container_id

    def _create_artifacts(self, alert, container_id):
        """ This function is used to create artifacts in given container using alert data.
        :param alert: Data of single alert
        :param container_id: ID of container in which we have to create the artifacts
        :return: status(success/failure), message
        """
        artifacts_list = []
        temp_dict = {}
        cef = {}

        # List to transform the data to CEF acceptable fields.
        transforms = {'hostname': 'sourceHostName', 'primary_ip_address': 'sourceAddress', 'file-path': 'filePath', 'file_full_path': 'filePath',
        'path': 'filePath', 'md5sum': 'fileHashMd5', 'sha1sum': 'fileHashSha1', 'sha256sum': 'fileHashSha256', 'original-file-name': 'fileName',
        'creation-time': 'fileCreateTime', 'modification-time': 'fileModificationTime', 'size-in-bytes': 'fileSize'}

        # Process the details section.
        details = json.loads(alert['data']['entires'])
        for detail in details['data']['entries'].items():
            if detail[0] in transforms:
                cef[transforms[detail[0]]] = detail[1]
            else:
                cef[detail[0]] = detail[1]

        # Process the rest of the alert
        for artifact_name, artifact_value in alert.items():
            if artifact_name in transforms:
                cef[transforms[artifact_name]] = artifact_value
            else:
                cef[artifact_name] = artifact_value

        # Add into artifacts dictionary if it is available
        if cef:
            temp_dict['cef'] = cef
            temp_dict['name'] = alert['data']['entires']['assessment']
            temp_dict['container_id'] = container_id
            temp_dict['source_data_identifier'] = self._create_dict_hash(temp_dict)

        artifacts_list.append(temp_dict)

        create_artifact_status, create_artifact_msg, _ = self.save_artifact(temp_dict)

        if phantom.is_fail(create_artifact_status):
            return self.set_status(phantom.APP_ERROR), create_artifact_msg

        return self.set_status(phantom.APP_SUCCESS), 'Artifacts created successfully'

    def _create_dict_hash(self, input_dict):
        """ This function is used to generate the hash from dictionary.
        :param input_dict: Dictionary for which we have to generate the hash
        :return: hash
        """
        if not input_dict:
            return None

        try:
            input_dict_str = json.dumps(input_dict, sort_keys=True)
        except Exception as e:
            self.debug_print('Handled exception in _create_dict_hash', e)
            return None

        return hashlib.md5(input_dict_str).hexdigest()

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.
        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'list_alerts': self._handle_list_alerts,
            'get_alert': self._handle_get_alert,
            'list_email_attributes': self._handle_list_email_attributes,
            'get_email_attributes': self._handle_get_email_attributes,
            'trace_email': self._handle_trace_email,
            'get_email': self._handle_get_email,
            'get_pcap': self._handle_get_pcap,
            'get_malware_files': self._handle_get_malware_files,
            'get_case_files': self._handle_get_case_files,
            'remediate_emails': self._handle_remediate_emails,
            'get_quarantined_email': self._handle_get_quarantined_email,
            'unquarantine_email': self._handle_unquarantine_email,
            'delete_quarantined_email': self._handle_delete_quarantined_email,
            'list_quarantined_emails': self._handle_list_quarantined_emails,
            'on_poll': self._handle_on_poll
        }

        # Get the action that we are supposed to execute for this App Run
        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping.keys():
            action_function = action_mapping[action]
            action_execution_status = action_function(param)
        return action_execution_status

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
        self._header = {
            'x-fireeye-api-key': config.get('api_key', '')
        }

        self._zip_password = config.get('zip_password', 'infected')

        base_url = ""

        # Check to see which instance the user selected. Use the appropate URL.
        instance = config.get('base_url')

        if instance == "US Instance":
            base_url = FIREEYEETP_US_BASE_PATH
        elif instance == "EMEA Instance":
            base_url = FIREEYEETP_EU_BASE_PATH
        elif instance == "APJ Instance":
            base_url = FIREEYEETP_AP_BASE_PATH

        self._base_url = base_url + FIREETEETP_API_PATH

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
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

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = FireeyeEtpConnector._get_phantom_base_url() + '/login'

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

        connector = FireeyeEtpConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
