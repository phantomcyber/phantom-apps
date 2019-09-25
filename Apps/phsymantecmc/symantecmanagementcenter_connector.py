# File: symantecmanagementcenter_connector.py
# Copyright (c) 2019 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

import requests
import json
from bs4 import BeautifulSoup
from bs4 import UnicodeDammit


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
            url = 'http://' + url

        return phantom.is_url(url.strip())

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR,
                "Empty response and no information in the header"), None)

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

        message = "Status Code: {0}. Data from server:\n{1}\n".format(
            status_code, error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message),
                      None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to parse JSON response. Error: {0}".format(
                        str(e))), None)

        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}'))

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
            r.text.replace('{', '{{').replace('}', '}}'))

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
            auth = (config.get('username'), config.get('password'))

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
        except Exception as e:
            self.debug_print("In rest call. {0}".format(str(e)))
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error Connecting to server. Details: {0}".format(str(e.message)), resp_json))

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        self.save_progress("Connecting to Symantec Management Center endpoint")

        success = self._handle_get_version(param)

        if not (success):
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

        if with_detail and not (param.get('name') or param.get('reference_id') or param.get('uuid')):
            return action_result.set_status(
                                    phantom.APP_ERROR, '"get policy" requires one of the following parameters to be supplied: policy name, policy uuid, policy reference id')

        try:
            response = self.get_policy_info(param, with_detail, action_result)
        except Exception as err:
            return action_result.set_status(
                phantom.APP_ERROR,
                ('Unable to retrieve policy info: ' + err.message))

        action_result.add_data(response)

        return action_result.set_status(
            phantom.APP_SUCCESS,
            'Successfully retrieved ' + str(len(response)) + ' policies')

    def get_policy_info(self, param, with_detail, action_result):
        reference_id = param.get('reference_id')
        name = param.get('name')
        uuid = param.get('uuid')
        content_type = param.get('content_type')

        if reference_id:
            reference_id = UnicodeDammit(reference_id).unicode_markup.encode('utf-8')

        if name:
            name = UnicodeDammit(name).unicode_markup.encode('utf-8')

        if uuid:
            uuid = UnicodeDammit(uuid).unicode_markup.encode('utf-8')

        if content_type:
            content_type = UnicodeDammit(content_type).unicode_markup.encode('utf-8')

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

        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            raise Exception('Could not retrieve policy information. Details: {0}'.format(str(response) if response else 'No details'))

        if uuid:
            response = [response]

        if with_detail:
            response = self._get_policy_details(response, action_result)

        return {'policies': response}

    def _get_policy_details(self, policies, action_result):
        for policy in policies:
            ret_val, response = self._make_rest_call(
                '/api/policies/' + policy['uuid'] + '/content', action_result)

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

    def _handle_add_url(self, param):

        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id = self.get_container_id()
        action_name = self.get_action_name()
        run_id = self.get_app_run_id()

        url = param['url'].lower().replace('http://',
                                           '').replace('https://', '')
        category = param['category']
        add_category = param.get('add_category')

        comment = 'Added by Phantom - Container ({0}) Action Name ({1}) Run ID ({2})'.format(
            container_id, action_name, run_id) + (
                ' - ' + param.get('comment') if param.get('comment') else '')
        uuid = param['uuid']

        try:
            policy_details = self.get_policy_info(param, True, action_result)
        except Exception as err:
            return action_result.set_status(
                phantom.APP_ERROR,
                ('Unable to retrieve policy info: ' + err.message))

        if len(policy_details) < 1:
            return action_result.set_status(
                phantom.APP_ERROR,
                ('Unable to find policy with uuid of ' + uuid))

        policy_details = policy_details['policies'][0]

        if policy_details['contentType'] != 'LOCAL_CATEGORY_DB':
            message = 'Unable to edit policy, wrong content type. Received content-type:{0}, expecting LOCAL_CATEGORY_DB'.format(policy_details['contentType'])
            return action_result.set_status(phantom.APP_ERROR, message)

        message = None

        try:
            policy_details, message = self._edit_policy_details(policy_details, url, category, uuid, 'add', action_result, add_category=add_category, comment=comment)
        except Exception as err:
            return action_result.set_status(phantom.APP_ERROR, ('Unable to edit policy. Error: {0}'.format(err.message)))

        summary = {'app_run_id': run_id, 'action_name': action_name}

        action_result.update_summary(summary)

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _edit_policy_details(self, policy_details, url, category, uuid, edit_type, action_result, add_category=False, comment=None):
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
                message = 'Category (' + category + ') removed'
            else:
                message = 'Category (' + category + ') was not found'
        else:
            for p_category in policy_details['policy_details']['content']['categories']:
                if (category == p_category['name'] or (edit_type == 'remove' and not (category))):
                    if edit_type == 'add':
                        for c_url in p_category['entries']:
                            if url == c_url['url']:
                                message = 'URL: ({0}). Already exists in the category: ({1})'.format(url, category)
                                break

                        if not (message):
                            p_category['entries'].append({'url': url, 'comment': comment, 'type': 'url'})
                            message = 'URL (' + url + ') added to category (' + category + ')'
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
                    message = 'Added category (' + category + ') and url (' + url + ')'
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

        ret_val, response = self._make_rest_call('/api/policies/{0}/content'.format(uuid), action_result, method='post', data=json.dumps(post_data))

        if phantom.is_fail(ret_val):
            raise Exception('Unable to {0} url/category. Details: {1}'.format(edit_type, str(response)))

        policy_details['policy_details']['revisionInfo'] = response['revisionInfo']

        action_result.add_data([policy_details])

        return policy_details, message

    def _handle_remove_url(self, param):

        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        url = param.get('url')
        category = param.get('category')
        uuid = param.get('uuid')

        if not (url or category):
            return action_result.set_status(phantom.APP_ERROR, '"remove listitem" requires a url and/or category be supplied')

        if url and not (category or param.get('delete_all')):
            return action_result.set_status(phantom.APP_ERROR, 'If no category is provided, delete_all must be checked')

        if category and not (url or param.get('delete_all')):
            return action_result.set_status(phantom.APP_ERROR, 'If no url is provided, delete_all must be checked to delete entire category')

        try:
            policy_details = self.get_policy_info(param, True, action_result)
        except Exception as err:
            return action_result.set_status(phantom.APP_ERROR, 'Unable to retrieve policy info: {0}'.format(err.message))

        policy_details = policy_details['policies'][0]

        if policy_details['contentType'] != 'LOCAL_CATEGORY_DB':
            message = 'Unable to edit policy, wrong content type. Received: {0}, expecting LOCAL_CATEGORY_DB'.format(policy_details['contentType'])
            return action_result.set_status(phantom.APP_ERROR, message)

        try:
            policy_details, message = self._edit_policy_details(policy_details, url, category, uuid, 'remove', action_result, add_category=False)
        except Exception as err:
            return action_result.set_status(phantom.APP_ERROR, 'Unable to edit policy: {0}'.format(err.message or ''))

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

        elif action_id == 'remove_url':
            ret_val = self._handle_remove_url(param)

        elif action_id == 'add_url':
            ret_val = self._handle_add_url(param)

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

        self._base_url = UnicodeDammit(config.get('base_url')).unicode_markup.encode('utf-8')

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
