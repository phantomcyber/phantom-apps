# File: symantecmanagementcenter_connector.py
#
# Copyright (c) 2019-2020 Splunk Inc.
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

import requests
import json
import sys
from bs4 import BeautifulSoup
from bs4 import UnicodeDammit
from symantecmanagementcenter_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class SymantecManagementCenterConnector(BaseConnector):
    def __init__(self):

        # Call the BaseConnectors init first
        super(SymantecManagementCenterConnector, self).__init__()

        self._state = None
        self._base_url = None

    def _validate_url(self, url):
        if not ('http' in url.lower() or 'https' in url.lower()):
            url = 'http://{}'.format(url)

        return phantom.is_url(url.strip())

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.
        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """

        try:
            if input_str and self._python_version == 2:

                input_str = UnicodeDammit(
                    input_str).unicode_markup.encode('utf-8')
        except:
            self.debug_print(
                "Error occurred while handling python 2to3 compatibility for the input string")

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
            self.debug_print("Error occurred while parsing error message")
            error_text = PARSE_ERR_MSG

        return error_text

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR,
                "Status Code: {}. Empty response and no information in the header".format(response.status_code)), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(
            status_code, self._handle_py_ver_compat_for_input_str(error_text))

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message),
                      None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to parse JSON response. Error: {0}".format(err), None))

        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            self._handle_py_ver_compat_for_input_str(r.text.replace('{', '{{').replace('}', '}}')))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message),
                      None)

    def _process_response(self, r, action_result):

        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # It's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # Everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            self._handle_py_ver_compat_for_input_str(r.text.replace('{', '{{').replace('}', '}}')))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message),
                      None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()
        auth = None
        headers = {}

        if config.get('api_token'):
            headers = {"X-Auth-Token": config.get('api_token')}
        else:
            auth = (self._handle_py_ver_compat_for_input_str(config.get('username')), config.get('password'))

        if method == 'post':
            headers['Accept'] = 'application/json'
            headers['Content-Type'] = 'application/json'

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR,
                                         "Invalid method: {0}".format(method)),
                resp_json)

        # Create a URL to connect to
        url = '{0}{1}'.format(self._base_url, endpoint)

        try:
            r = request_func(
                url,
                auth=auth,  # basic authentication
                headers=headers,
                verify=config.get('verify_server_cert', False),
                **kwargs)
        except requests.exceptions.InvalidSchema:
            error_message = 'Error connecting to server. No connection adapters were found for %s' % (url)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except requests.exceptions.InvalidURL:
            error_message = 'Error connecting to server. Invalid URL %s' % (url)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.debug_print("In rest call. {0}".format(err))
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error Connecting to server. Details: {0}".format(err), resp_json))

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        self.save_progress("Connecting to Symantec Management Center endpoint")

        success = self._handle_get_version(param)
        if not success:
            self.save_progress("Test Connectivity Failed")
        else:
            self.save_progress("Test Connectivity Passed")

        return success

    def _handle_get_version(self, param):
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, response = self._make_rest_call('/api/system/version',
                                                 action_result)

        if (phantom.is_fail(ret_val)):
            if self.get_action_identifier() == 'test_connectivity':
                return action_result.set_status(phantom.APP_ERROR, 'Could not retrieve Management Center version. Failed to connect to endpoint')
            else:
                return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS,
                                        'Successfully retrieved Version info')

    def _handle_list_policies(self, param, with_detail=False):
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        if with_detail and not (self._handle_py_ver_compat_for_input_str(param.get('name')) or self._handle_py_ver_compat_for_input_str(
         param.get('reference_id')) or self._handle_py_ver_compat_for_input_str(param.get('uuid'))):
            return action_result.set_status(
                phantom.APP_ERROR, '"get policy" requires one of the following parameters to be supplied: "policy_name", "policy_uuid", "policy_reference_id"')

        try:
            response = self.get_policy_info(param, with_detail, action_result)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR,
                ('Unable to retrieve policy info: {}'.format(err)))

        action_result.add_data(response)

        return action_result.set_status(
            phantom.APP_SUCCESS,
            'Successfully retrieved {0} policies'.format(len(response['policies'])))

    def get_policy_info(self, param, with_detail, action_result):
        reference_id = self._handle_py_ver_compat_for_input_str(param.get('reference_id'))
        name = self._handle_py_ver_compat_for_input_str(param.get('name'))
        uuid = self._handle_py_ver_compat_for_input_str(param.get('uuid'))
        content_type = self._handle_py_ver_compat_for_input_str(param.get('content_type'))

        self.debug_print("Parameters received in 'get_policy_info': {}".format([reference_id, name, uuid, content_type]))
        params = {}

        endpoint = '/api/policies'

        if content_type:
            params['contentType'] = 'EQ {0}'.format(content_type)

        if reference_id:
            params['referenceId'] = 'EQ {0}'.format(reference_id)

        if name:
            params['name'] = 'EQ {0}'.format(name)

        if uuid:
            endpoint = '{0}/{1}'.format(endpoint, uuid)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            raise Exception('Could not retrieve policy information. Details: {0}'.format(self._handle_py_ver_compat_for_input_str(response) if response else 'No details'))

        if uuid:
            response = [response]

        if with_detail:
            response = self._get_policy_details(response, action_result)

        return {'policies': response}

    def _get_policy_details(self, policies, action_result):
        for policy in policies:
            ret_val, response = self._make_rest_call(
                '/api/policies/{}/content'.format(policy['uuid']), action_result)

            if phantom.is_fail(ret_val):
                raise Exception('Could not retrieve policy details for: {0}/{1}'.format(policy['name'], policy['uuid']))

            policy['policy_details'] = response

        return policies

    def _handle_unblock_ip(self, param):

        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param['ip']
        self.debug_print(ip)

        ret_val, response = self._make_rest_call('/endpoint', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            pass

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_remove_category(self, param):

        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        category = param['category']
        self.debug_print(category)

        ret_val, response = self._make_rest_call('/policies', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            pass

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_add_content(self, param):

        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id = self.get_container_id()
        action_name = self.get_action_name()
        run_id = self.get_app_run_id()

        url = self._handle_py_ver_compat_for_input_str(param.get('url'))
        ip = self._handle_py_ver_compat_for_input_str(param.get('ip'))

        content = url or ip
        if not content:
            return action_result.set_status(
                phantom.APP_ERROR, "Please provide input in either 'url' or 'ip' action parameter"
            )

        content = content.lower().replace('http://',
                                              '').replace('https://', '')
        category = self._handle_py_ver_compat_for_input_str(param.get('category'))
        add_category = param.get('add_category')

        comment = 'Added by Phantom - Container ({0}) Action Name ({1}) Run ID ({2})'.format(
            container_id, action_name, run_id) + (
                ' - ' + self._handle_py_ver_compat_for_input_str(param.get('comment')) if param.get('comment') else '')
        uuid = self._handle_py_ver_compat_for_input_str(param['uuid'])

        try:
            policy_details = self.get_policy_info(param, True, action_result)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR,
                ('Unable to retrieve policy info: {}'.format(err)))

        if len(policy_details) < 1:
            return action_result.set_status(
                phantom.APP_ERROR,
                ('Unable to find policy with uuid of {}'.format(uuid)))

        try:
            policy_details = policy_details['policies'][0]
            if policy_details['contentType'] not in CONTENT_TYPES:
                message = 'Unable to edit policy, wrong content type. Received content-type:{0}, expecting LOCAL_CATEGORY_DB, URL_LIST'.format(
                    policy_details['contentType'])
                return action_result.set_status(phantom.APP_ERROR, message)
        except:
            return action_result.set_status(phantom.APP_ERROR, "An error occurred while processing policy details response from server")

        if policy_details['contentType'] == 'IP_LIST':
            if ip is None:
                return action_result.set_status(phantom.APP_ERROR, 'The policy you are attempting to edit is a IP_LIST Shared Object, but no "ip" was provided')
        else:
            if url is None:
                return action_result.set_status(phantom.APP_ERROR, 'The policy you are attempting to edit requires a "url", but none was provided')

        message = None

        try:
            policy_details, message = self._edit_policy_details(
                policy_details, content, category, uuid, 'add', action_result, add_category=add_category, comment=comment)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, ('Unable to edit policy. Error: {0}'.format(err)))

        summary = {'app_run_id': run_id, 'action_name': action_name}

        action_result.update_summary(summary)

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _edit_policy_details(self, policy_details, content, category, uuid, edit_type, action_result, add_category=False, comment=None):
        message = None

        post_data = {}

        if policy_details['contentType'] == 'LOCAL_CATEGORY_DB':
            post_data, message = self._edit_local_category_db_content(policy_details, content, category, uuid, edit_type, action_result, add_category, comment)
        elif policy_details['contentType'] == 'IP_LIST':
            post_data, message = self._edit_ip_list_content(policy_details, content, category, uuid, edit_type, action_result, add_category, comment)
        elif policy_details['contentType'] == 'URL_LIST':
            post_data, message = self._edit_url_list_content(policy_details, content, category, uuid, edit_type, action_result, add_category, comment)

        ret_val, response = self._make_rest_call('/api/policies/{0}/content'.format(uuid), action_result, method='post', data=json.dumps(post_data))

        if phantom.is_fail(ret_val):
            raise Exception('Unable to {0} url/category. Details: {1}'.format(edit_type, self._handle_py_ver_compat_for_input_str(response) if response else 'No details'))

        policy_details['policy_details']['revisionInfo'] = response['revisionInfo']
        action_result.add_data([policy_details])

        return policy_details, message

    def _edit_ip_list_content(self, policy_details, ip, category, uuid, edit_type, action_result, add_category, comment):
        message = None

        if edit_type == 'remove':
            policy_details['policy_details']['content']['ipAddresses'] = [
                ipobj for ipobj
                in policy_details['policy_details']['content']['ipAddresses']
                if ipobj['ipAddress'] != ip
            ]
            message = 'IP removed from policy ({0} - UUID: {1})'.format(policy_details['name'], policy_details['uuid'])
        else:
            if len([ipobj for ipobj
                    in policy_details['policy_details']['content']['ipAddresses']
                    if ipobj['ipAddress'] == ip
                    ]) == 0:
                policy_details['policy_details']['content']['ipAddresses'].append(
                    {
                        "description": comment,
                        "ipAddress": ip,
                        "enabled": True
                    }
                )
                message = 'IP added to policy ({0} - UUID: {1})'.format(policy_details['name'], policy_details['uuid'])
            else:
                message = 'IP already exists in policy ({0} - UUID: {1})'.format(policy_details['name'], policy_details['uuid'])

        post_data = {
            'content': policy_details['policy_details']['content'],
            'contentType': policy_details['contentType'],
            'schemaVersion': policy_details['policy_details']['schemaVersion'],
            'changeDescription': 'Updated by Phantom - Details: {0}'.format(comment)
        }

        return post_data, message

    def _edit_url_list_content(self, policy_details, url, category, uuid, edit_type, action_result, add_category, comment):
        message = None

        if edit_type == 'remove':
            policy_details['policy_details']['content']['urls'] = [
                urlobj for urlobj
                in policy_details['policy_details']['content']['urls']
                if urlobj['url'].lower() != url.lower()
            ]
            message = 'URL removed from policy ({0} - UUID: {1})'.format(policy_details['name'], policy_details['uuid'])
        else:
            if len([urlobj for urlobj
                    in policy_details['policy_details']['content']['urls']
                    if urlobj['url'].lower() == url.lower()
                    ]) == 0:
                policy_details['policy_details']['content']['urls'].append(
                    {
                        "description": comment,
                        "url": url,
                        "enabled": True
                    }
                )
                message = 'URL added to policy ({0} - UUID: {1})'.format(policy_details['name'], policy_details['uuid'])
            else:
                message = 'URL already exists in policy ({0} - UUID: {1})'.format(policy_details['name'], policy_details['uuid'])

        post_data = {
            'content': policy_details['policy_details']['content'],
            'contentType': policy_details['contentType'],
            'schemaVersion': policy_details['policy_details']['schemaVersion'],
            'changeDescription': 'Updated by Phantom - Details: {0}'.format(comment)
        }

        return post_data, message

    def _edit_local_category_db_content(self, policy_details, url, category, uuid, edit_type, action_result, add_category, comment):
        message = None

        if edit_type == 'remove' and not (url):
            cat_num = len(
                policy_details['policy_details']['content']['categories'])
            policy_details['policy_details']['content']['categories'] = [
                cat for cat in policy_details['policy_details']['content']
                ['categories'] if cat['name'] != category
            ]
            if cat_num != len(
                    policy_details['policy_details']['content']['categories']):
                message = 'Category ({}) removed'.format(category)
            else:
                message = 'Category ({}) was not found'.format(category)
        else:
            for p_category in policy_details['policy_details']['content']['categories']:
                if (category == p_category['name'] or (edit_type == 'remove' and not (category))):
                    if edit_type == 'add':
                        for c_url in p_category['entries']:
                            if url == c_url['url']:
                                message = 'URL: ({0}). Already exists in the category: ({1})'.format(url, category)
                                break

                        if not message:
                            p_category['entries'].append({'url': url, 'comment': comment, 'type': 'url'})
                            message = 'URL ({0}) added to category ({1})'.format(url, category)
                            break
                    elif edit_type == 'remove':
                        cat_len = len(p_category['entries'])
                        p_category['entries'] = [entry for entry in p_category['entries'] if entry['url'] != url]

                        if len(p_category['entries']) != cat_len:
                            message = 'Message: {0}, URL ({1}) removed from category ({2}). '.format(message or '', url, p_category['name'])

            if message is None and edit_type == 'add':
                if add_category:
                    policy_details['policy_details']['content'][
                        'categories'].append({
                            'type':
                            'inline',
                            'name':
                            category,
                            'entries': [{
                                'url': url,
                                'type': 'url',
                                'comment': comment
                            }]
                        })
                    message = 'Added category ({0}) and url ({1})'.format(category, url)
                else:
                    e = 'Category ({0}) does not exist. {1}'.format(category, 'If you would like to add it, use the "add_category" parameter' if edit_type == 'Add' else '')
                    raise Exception(e)
            elif message is None and edit_type == 'remove':
                message = 'Unable to find Category ({0}) and url ({1}) combination'.format(category or '', url or '')

        post_data = {
            'content': policy_details['policy_details']['content'],
            'contentType': policy_details['contentType'],
            'schemaVersion': policy_details['policy_details']['schemaVersion'],
            'changeDescription': 'Updated by Phantom - Details: {0}'.format(comment)
        }

        return post_data, message

    def _handle_remove_content(self, param):

        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        url = self._handle_py_ver_compat_for_input_str(param.get('url'))
        ip = self._handle_py_ver_compat_for_input_str(param.get('ip'))
        category = self._handle_py_ver_compat_for_input_str(param.get('category'))
        uuid = self._handle_py_ver_compat_for_input_str(param.get('uuid'))

        content = url or ip
        if not content:
            return action_result.set_status(
                phantom.APP_ERROR, "Please provide input in either 'url' or 'ip' action parameter"
            )

        content = content.lower().replace('http://',
                                              '').replace('https://', '')
        try:
            policy_details = self.get_policy_info(param, True, action_result)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, 'Unable to retrieve policy info: {0}'.format(err))

        try:
            policy_details = policy_details['policies'][0]
            if policy_details['contentType'] not in CONTENT_TYPES:
                message = 'Unable to edit policy, wrong content type. Received: {0}, expecting LOCAL_CATEGORY_DB, URL_LIST, or IP_LIST'.format(policy_details['contentType'])
                return action_result.set_status(phantom.APP_ERROR, message)
        except:
            return action_result.set_status(phantom.APP_ERROR, "An error occurred while processing policy details response from server")

        if policy_details['contentType'] == 'LOCAL_CATEGORY_DB':
            if not (url or category):
                return action_result.set_status(phantom.APP_ERROR, '"remove listitem" requires a "url" and/or "category" be supplied')

            if url and not (category or param.get('delete_all')):
                return action_result.set_status(phantom.APP_ERROR, 'If no "category" is provided, "delete_all" must be checked')

            if category and not (url or param.get('delete_all')):
                return action_result.set_status(phantom.APP_ERROR, 'If no "url" is provided, "delete_all" must be checked to delete entire category')
        elif policy_details['contentType'] == 'IP_LIST':
            if ip is None:
                return action_result.set_status(phantom.APP_ERROR, 'The policy you are attempting to edit is a IP_LIST Shared Object, but no "ip" was provided')
        else:
            if url is None:
                return action_result.set_status(phantom.APP_ERROR, 'The policy you are attempting to edit is a URL_LISTS Shared Object, but no "url" was provided')

        try:
            policy_details, message = self._edit_policy_details(
                policy_details, content, category, uuid, 'remove', action_result, add_category=False)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, 'Unable to edit policy: {0}'.format(err or ''))

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_list_urls(self, param):

        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        category = param.get('category', '')
        self.debug_print(category)

        ret_val, response = self._make_rest_call('/policies', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            pass

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'get_version':
            ret_val = self._handle_get_version(param)

        elif action_id == 'list_policies':
            ret_val = self._handle_list_policies(param)

        elif action_id == 'get_policy':
            ret_val = self._handle_list_policies(param, with_detail=True)

        # this also handles aremoving IPs, legacy naming though
        elif action_id == 'remove_url':
            ret_val = self._handle_remove_content(param)

        # this also handles adding IPs, legacy naming though
        elif action_id == 'add_url':
            ret_val = self._handle_add_content(param)

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
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version")

        self._base_url = self._handle_py_ver_compat_for_input_str(config.get('base_url'))

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
            login_url = SymantecManagementCenterConnector._get_phantom_base_url(
            ) + '/login'

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
            r2 = requests.post(login_url, verify=False, data=data, mheaders=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SymantecManagementCenterConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
