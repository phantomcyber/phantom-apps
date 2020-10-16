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

# Usage of the consts file is recommended
# from docker_v3_consts import *
import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class Docker_V3Connector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(Docker_V3Connector, self).__init__()

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
                phantom.APP_ERROR,
                "Empty response and no information in the header"
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
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(
            status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')
        return RetVal(action_result.set_status(
                                        phantom.APP_ERROR,
                                        message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = """Error from server.
            Status Code: {0} Data from server: {1}""".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(
                                        phantom.APP_ERROR,
                                        message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data,
        # it will get dumped in the logs if the action fails
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
        message = """Can't process response from server.
            Status Code: {0} Data from server: {1}""".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(
                                        phantom.APP_ERROR,
                                        message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional
        # parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(
                phantom.APP_ERROR,
                "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                verify=config.get('verify_server_cert', False),
                **kwargs
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _make_post_call(self,
                        endpoint, action_result, method="post", **kwargs):
        # **kwargs can be any additional
        # parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(
                phantom.APP_ERROR,
                "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self._base_url + endpoint
        try:
            if 'data' in kwargs:
                k_data = json.loads(kwargs['data'])
                r = request_func(
                    url,
                    verify=config.get("verify_server_cert", False),
                    json=k_data
                )
            else:
                # response = "parameters = {0}"
                # response_dict = {'parameters': response}
                # action_result.add_data(response_dict)
                # summary = action_result.update_summary({})
                # summary['parameters_data'] = response
                r = request_func(
                    url,
                    # auth=(username, password),  # basic authentication
                    verify=config.get('verify_server_cert', False),
                    **kwargs
                )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )
        r.status_code = 200
        return self._process_response(r, action_result)

    def _cleanup_row_values(self, row):
        # The MySQL column values is supposed
        # to be a bytearray as opposed to a string
        return {k: v.decode('utf-8')
                if type(v) == bytearray else v for k, v in row.items()}

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector)
        # to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("obtaining the version of the docker host")
        # make rest call
        ret_val, response = self._make_rest_call('/version', action_result)
        res = json.dumps(response)

        indices = [i + 1 for i, elem in enumerate(res) if elem == ',']
        indices.insert(0, 0)
        indices.insert(len(indices), len(res))
        for i in range(len(indices) - 1):
            self.save_progress(res[indices[i]:indices[i + 1]])
        self.save_progress(self._base_url)
        # action_result.add_data(response)
        # self.save_progress("{0}".len(response))
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed,
            # action result should contain all the error details
            # for now the return is commented out, but after implementation,
            # return from here
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        # self.save_progress("version".format(ret_val)
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message,
        # in case of success we don't set the message, but use the summary
        # return action_result.set_status(phantom.APP_ERROR,
        # "Action not yet implemented")

    def _handle_get_changes_of_a_container_filesystem(self, param):
        # Implement the handler here
        # use self.save_progress(...)
        # to send progress messages back to the platform
        self.save_progress(
                """In action handler
                for: {0}""".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector)
        # to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        id = param['id']

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make rest call
        ret_val, response = self._make_rest_call(
            '/containers/{0}/changes'.format(id), action_result)

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed,
            # action result should contain all the error details
            # for now the return is commented out,
            # but after implementation, return from here
            return action_result.get_status()
            # pass

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        response_dict = {'filesystem': response}
        action_result.add_data(response_dict)

        # Add a dictionary that is made up of the most
        # important values from data into the summary
        summary = action_result.update_summary({})
        summary['filesystem_data'] = json.dumps(response, indent=1)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a
        # textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message,
        # in case of success we don't set the message, but use the summary
        # return action_result.set_status
        # (phantom.APP_ERROR, "Action not yet implemented")

    def _handle_inspect_a_container(self, param):
        # Implement the handler here
        # use self.save_progress(...)
        # to send progress messages back to the platform
        self.save_progress("""In action
        handler for: {0}""".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector)
        # to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        # required_parameter = param['required_parameter']

        # Optional values should use the .get() function
        id = param.get('id', '')
        size = param.get('size', '')

        # make rest call
        ret_val, response = self._make_rest_call(
            '/containers/{0}/json?size={1}'.format(id, size), action_result)

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed,
            # action result should contain all the error details
            # for now the return is commented out,
            # but after implementation, return from here
            return action_result.get_status()
            # pass

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        response_dict = {'containerStats': response['HostConfig']}
        action_result.add_data(response_dict)

        # Add a dictionary that is made up of the most
        # important values from data into the summary
        summary = action_result.update_summary({})
        summary['containerStats_data'] = """Please view the results
                                            in the results data section"""

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual
        # message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message,
        # in case of success we don't set the message, but use the summary

    def _handle_update_a_container(self, param):
        # Implement the handler here
        self.save_progress("""In action
        handler for: {0}""".format(self.get_action_identifier()))

        # Add an action result object to self
        # (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        id = param['id']
        # request_body = param['request_body']
        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')
        # response = "request body={0}".format(request_body)
        # make rest call
        ret_val, response = self._make_post_call(
            '/containers/{0}/update'.format(id),
            action_result,
            data=param['request_body'])

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed,
            # action result should contain all the error details
            # for now the return is commented out,
            # but after implementation, return from here
            return action_result.get_status()
        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        response_dict = {'update_stats': response}
        action_result.add_data(response_dict)

        # Add a dictionary that is made up of the most
        # important values from data into the summary
        summary = action_result.update_summary({})
        summary['update_data'] = json.dumps(response, indent=1)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message
        # based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message,
        # in case of success we don't set the message, but use the summary

    def _handle_restart_a_container(self, param):
        # Implement the handler here
        self.save_progress("""In action
        handler for: {0}""".format(self.get_action_identifier()))

        # Add an action result object to self
        # (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        id = param['id']

        # Optional values should use the .get() function
        t = param.get('t', '')

        # make rest call
        ret_val, response = self._make_post_call(
            '/containers/{0}/restart?t={1}'.format(id, t), action_result)
        response = "container {0} has restarted".format(id)
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed,
            # action result should contain all the error details
            # for now the return is commented out,
            # but after implementation, return from here
            return action_result.get_status()
            # pass

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        response_dict = {'restart_stats': response}
        action_result.add_data(response_dict)
        # Add a dictionary that is made up of the most
        # important values from data into the summary
        summary = action_result.update_summary({})
        summary['restart_data'] = response

        # Return success, no need to set the message, only the status
        # BaseConnector will create a
        # textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message,
        # in case of success we don't set the message, but use the summary

    def _handle_export_a_container(self, param):
        # Implement the handler here
        self.save_progress("""In action
        handler for: {0}""".format(self.get_action_identifier()))

        # Add an action result object to self
        # (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        ID = param['id']

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make rest call
        ret_val, response = self._make_rest_call(
            '/containers/{0}/export'.format(ID), action_result)
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed,
            # action result should contain all the error details
            # for now the return is commented out,
            # but after implementation, return from here
            return action_result.get_status()
            # pass

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        response_dict = {'export_stat': response}
        action_result.add_data(response_dict)

        # Add a dictionary that is made up of the
        # most important values from data into the summary
        summary = action_result.update_summary({})
        summary['expoort_data'] = len(action_result['data'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual
        # message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message,
        # in case of success we don't set the message, but use the summary

    def _handle_list_container(self, param):
        # Implement the handler here
        self.save_progress("""In action
        handler for: {0}""".format(self.get_action_identifier()))

        # Add an action result object to self
        # (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        # required_parameter = param['required_parameter']

        # Optional values should use the .get() function
        all = param.get('all', '')
        limit = param.get('limit', '')
        size = param.get('size', '')
        filters = param.get('filters', '')

        # make rest call
        ret_val, response = self._make_rest_call(
            '/containers/json?all={0}&limit={1}&size={2}&filters={3}'.format(
                                                    all,
                                                    limit,
                                                    size,
                                                    filters), action_result)

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed,
            #  action result should contain all the error details
            # for now the return is commented out,
            # but after implementation, return from here
            return action_result.get_status()
            # pass

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section\
        response_dict = {'containers': response}
        action_result.add_data(response_dict)

        # Add a dictionary that is made up of the
        # most important values from data into the summary
        summary = action_result.update_summary({})
        summary['container_summary'] = [
                {'container ' + str(item):
                    {
                    'id': response_dict['containers'][item]['Id'],
                    'Name': response_dict['containers'][item]['Names'][0]}}
                for item in range(len(response_dict['containers']))]

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual
        # message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message,
        # in case of success we don't set the message, but use the summary

    def _handle_stop_a_container(self, param):
        # Implement the handler here
        self.save_progress("""In action
        handler for: {0}""".format(self.get_action_identifier()))

        # Add an action result object to self
        # (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        ID = param['id']

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make rest call
        ret_val, response = self._make_post_call(
            '/containers/{0}/stop'.format(ID), action_result)
        response = "container {0} has terminated".format(ID)
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed,
            # action result should contain all the error details
            # for now the return is commented out, but after implementation,
            # return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        response_dict = {'pause': response}
        action_result.add_data(response_dict)

        # Add a dictionary that is made up of the most
        # important values from data into the summary
        summary = action_result.update_summary({})
        summary['stop_data'] = response

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual
        # message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message,
        # in case of success we don't set the message, but use the summary

    def _handle_start_a_container(self, param):
        # Implement the handler here
        self.save_progress("""In action
        handler for: {0}""".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector)
        # to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        ID = param['id']

        # Optional values should use the .get() function
        detachkeys = param.get('detachkeys', '')
        # make rest call
        ret_val, response = self._make_post_call(
            '/containers/{0}/start?detachKeys={1}'.format(
                                                        ID,
                                                        detachkeys),
            action_result)
        response = "Container {0} has resumed".format(ID)
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed,
            # action result should contain all the error details
            # for now the return is commented out, but after implementation,
            # return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        response_dict = {'unpause': response}
        action_result.add_data(response_dict)
        # Add a dictionary that is made up of the
        # most important values from data into the summary
        summary = action_result.update_summary({})
        summary['unpause_data'] = response

        # Return success, no need to set the message, only the status
        # BaseConnector will create
        # a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message,
        # in case of success we don't set the message, but use the summary

    def _handle_list_images(self, param):
        # Implement the handler here
        self.save_progress("""In action
        handler for: {0}""".format(self.get_action_identifier()))

        # Add an action result object to self
        # (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        # required_parameter = param['required_parameter']

        # Optional values should use the .get() function
        all = param.get('all', '')
        filters = param.get('filters', '')
        digests = param.get('digests', '')
        # make rest call
        ret_val, response = self._make_rest_call(
            '/images/json?all={0}&filters={1}&digests={2}'.format(
                                                                all,
                                                                filters,
                                                                digests),
            action_result)

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed,
            # action result should contain all the error details
            # for now the return is commented out, but after implementation,
            # return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response_dict = {'images': response}
        action_result.add_data(response_dict)

        # Add a dictionary that is made up of
        # the most important values from data into the summary
        summary = action_result.update_summary({})
        # res = json.dumps(response)
        summary['image_data'] = [
                    {'images ' + str(item):
                        {'id': response_dict['images'][item]['Id'],
                            'Tags':
                                response_dict['images'][item]['RepoTags'][0]}}
                    for item in range(len(response_dict['images']))]
        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message
        # based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message,
        # in case of success we don't set the message,
        # but use the summary

    def _handle_rename_container(self, param):
        self.save_progress("""In action
        handler for: {0}""".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        ID = param['id']
        name = param['name']
        ret_val, response = self._make_post_call(
                '/containers/{0}/rename?name={1}'.format(
                                                        ID,
                                                        name),
                action_result)
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed,
            # action result should contain all the error details
            # for now the return is commented out,
            # but after implementation, return from here
            return action_result.get_status()
        response_dict = {'rename': response}
        action_result.add_data(response_dict)
        summary = action_result.update_summary({})
        summary['rename_data'] = response
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_kill_container(self, param):
        self.save_progress("""In action
        handler for: {0}""".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        ID = param['id']
        signal = param.get('signal', '')
        ret_val, response = self._make_post_call(
                    '/containers/{0}/kill?signal={1}'.format(
                        ID,
                        signal),
                    action_result)
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed,
            # action result should contain all the error details
            # for now the return is commented out,
            # but after implementation, return from here
            return action_result.get_status()
        response_dict = {'kill': response}
        action_result.add_data(response_dict)
        summary = action_result.update_summary({})
        summary['kill_data'] = response
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_remove_container(self, param):
        self.save_progress("""In action
        handler for: {0}""".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        ID = param['id']
        v = param.get('v', '')
        force = param.get('force', '')
        link = param.get('link', '')
        ret_val, response = self._make_post_call(
                    '/containers/{0}?v={1}&force={2}&link={3}'.format(
                        ID,
                        v,
                        force,
                        link),
                    action_result, method='delete')
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed,
            # action result should contain all the error details
            # for now the return is commented out,
            # but after implementation, return from here
            return action_result.get_status()
        response_dict = {'remove container': response}
        action_result.add_data(response_dict)
        summary = action_result.update_summary({})
        summary['remove_container_data'] = response
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_stopped_containers(self, param):
        self.save_progress("""In action
        handler for: {0}""".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        filters = param.get('filters', '')
        ret_val, response = self._make_post_call(
                    '/containers/prune?filters={0}'.format(filters),
                    action_result)
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed,
            # action result should contain all the error details
            # for now the return is commented out,
            # but after implementation, return from here
            return action_result.get_status()
        response_dict = {'prune': response}
        action_result.add_data(response_dict)
        # Add a dictionary that is made up of
        # the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['prune_data'] = response

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual
        # message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_remove_image(self, param):
        self.save_progress("""In action
        handler for: {0}""".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        name = param['name']
        force = param.get('force', '')
        noprune = param.get('noprune', '')
        ret_val, response = self._make_post_call(
                    '/images/{0}?force={1}&noprune={2}'.format(
                        name,
                        force,
                        noprune),
                    action_result, method='delete')
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed,
            # action result should contain all the error details
            # for now the return is commented out,
            # but after implementation, return from here
            return action_result.get_status()
        response_dict = {'delete image': response}
        action_result.add_data(response_dict)
        # Add a dictionary that is made
        # up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['delete_image_data'] = response

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual
        # message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_unused_images(self, param):
        self.save_progress("""In action
        handler for: {0}""".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        filters = param.get('filters', '')
        ret_val, response = self._make_post_call(
            '/images/prune?filters={0}'.format(filters), action_result)
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed,
            # action result should contain all the error details
            # for now the return is commented out,
            # but after implementation, return from here
            return action_result.get_status()
        response_dict = {'unused_images': response}
        action_result.add_data(response_dict)
        summary = action_result.update_summary({})
        summary['unused_images_data'] = response
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_image_history(self, param):
        self.save_progress("""In action
        handler for: {0}""".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        name = param['name']
        ret_val, response = self._make_rest_call(
            '/images/{0}/history'.format(name), action_result)
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed,
            # action result should contain all the error details
            # for now the return is commented out,
            # but after implementation, return from here
            return action_result.get_status()
        response_dict = {'history': response}
        action_result.add_data(response_dict)
        summary = action_result.update_summary({})
        summary['history_data'] = "For more detailed results please click in "
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_builder_cache(self, param):
        self.save_progress("""In action
        handler for: {0}""".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        keep_storage = param.get('keep-storage', '')
        all = param.get('all', '')
        filters = param.get('filters', '')
        ret_val, response = self._make_post_call(
                    '/build/prune?keep-storage={0}&all={1}&filters={2}'.format(
                        keep_storage,
                        all,
                        filters),
                    action_result)
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed,
            # action result should contain all the error details
            # for now the return is commented out,
            # but after implementation, return from here
            return action_result.get_status()
        response_dict = {'cache': response}
        action_result.add_data(response_dict)
        summary = action_result.update_summary({})
        # res = json.dumps(response)
        summary['cache_data'] = json.dumps(response, indent=1)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_snapshot_of_a_container(self, param):
        self.save_progress("""In action
        handler for: {0}""".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        container = param['container']
        repo = param.get('repo', '')
        tag = param.get('tag', '')
        comment = param.get('comment', '')
        author = param.get('author', '')
        pause = param.get('pause', '')
        changes = param.get('changes', '')
        rest_call_1 = '/commit?container={0}&repo={1}&tag={2}'
        rest_call_2 = '&comment={3}&author={4}&pause={5}'
        ret_val, response = self._make_post_call(
            rest_call_1 + rest_call_2.format(
                container, repo,
                tag, comment, author,
                pause, changes), action_result, data=param['request_body'])
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed,
            # action result should contain all the error details
            # for now the return is commented out,
            # but after implementation, return from here
            return action_result.get_status()
        response_dict = {'snapshot': response}
        action_result.add_data(response_dict)
        summary = action_result.update_summary({})
        summary['snapshot_data'] = response
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_a_container(self, param):
        self.save_progress("""In action
        handler for: {0}""".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        name = param['name']
        ret_val, response = self._make_post_call(
            '/containers/create?name={0}'.format(name),
            action_result, data=param['request_body'])
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed,
            # action result should contain all the error details
            # for now the return is commented out,
            # but after implementation, return from here
            return action_result.get_status()
        response_dict = {'create': response}
        action_result.add_data(response_dict)
        summary = action_result.update_summary({})
        summary['create_data'] = response
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'get_changes_of_a_container_filesystem':
            ret_val = self._handle_get_changes_of_a_container_filesystem(param)

        elif action_id == 'inspect_a_container':
            ret_val = self._handle_inspect_a_container(param)

        elif action_id == 'update_a_container':
            ret_val = self._handle_update_a_container(param)

        elif action_id == 'restart_a_container':
            ret_val = self._handle_restart_a_container(param)

        elif action_id == 'export_a_container':
            ret_val = self._handle_export_a_container(param)

        elif action_id == 'list_container':
            ret_val = self._handle_list_container(param)

        elif action_id == 'stop_a_container':
            ret_val = self._handle_stop_a_container(param)

        elif action_id == 'start_a_container':
            ret_val = self._handle_start_a_container(param)

        elif action_id == 'list_images':
            ret_val = self._handle_list_images(param)

        elif action_id == 'rename_container':
            ret_val = self._handle_rename_container(param)

        elif action_id == 'kill_container':
            ret_val = self._handle_kill_container(param)

        elif action_id == 'remove_container':
            ret_val = self._handle_remove_container(param)

        elif action_id == 'delete_stopped':
            ret_val = self._handle_delete_stopped_containers(param)
        elif action_id == 'remove_image':
            ret_val = self._handle_remove_image(param)
        elif action_id == 'delete_unused':
            ret_val = self._handle_delete_unused_images(param)
        elif action_id == 'image_history':
            ret_val = self._handle_image_history(param)
        elif action_id == 'delete_builder_cache':
            ret_val = self._handle_delete_builder_cache(param)
        elif action_id == 'snapshot_of_a_container':
            ret_val = self._handle_snapshot_of_a_container(param)
        elif action_id == 'create_a_container':
            ret_val = self._handle_create_a_container(param)
        return ret_val

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

        self._base_url = config['host ip']

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
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
        try:
            login_url = Docker_V3Connector._get_phantom_base_url() + '/login'

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
            r2 = requests.post(
                login_url,
                verify=False,
                data=data,
                headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("""Unable to get session
            id from the platform. Error: """ + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = Docker_V3Connector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
