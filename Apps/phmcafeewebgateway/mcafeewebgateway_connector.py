# File: mcafeewebgateway_connector.py
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from contextlib import suppress
from bs4 import BeautifulSoup
from bs4 import UnicodeDammit
from mcafeewebgateway_consts import *
import xmltodict
import requests
import json
import re


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class McafeeWebGatewayConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(McafeeWebGatewayConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._session_id = None
        self._verify = None

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
            error_msg = self._encode_unicode(error_msg)
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

    def _encode_unicode(self, string):
        return UnicodeDammit(string).unicode_markup.encode('utf-8')

    def _validate_integer(self, action_result, parameter, key):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MSG.format(key=key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MSG.format(key=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, NON_NEGATIVE_INTEGER_MSG.format(key=key)), None

        return phantom.APP_SUCCESS, parameter

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, 'Status code: {0}. Empty response and no information in the header'.format(response.status_code)), '')

    def _process_xml_response(self, r, action_result):
        try:
            if 200 <= r.status_code < 399:
                return RetVal(phantom.APP_SUCCESS, xmltodict.parse(self._encode_unicode(r.text)))

            else:
                message = f'Error from server. Status Code: {r.status_code} Data from server: {r.text}'.replace('{', '{{').replace('}', '}}')
        except Exception as err:
            message = f'Error parsing results data. Status Code: {r.status_code} Message - {err}; Data from server: {r.text}'

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), str(message))

    def _process_html_response(self, response, action_result) -> RetVal:

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = 'Cannot parse error details'

        message = f'Status Code: {status_code}. Data from server:\n{error_text}\n'.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), str(message))

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except ValueError as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, f'Unable to parse JSON response. Error: {err}'), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = f'Error from server. Status Code: {r.status_code} Data from server: {r.text}'.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), str(message))

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        # Process each 'Content-Type' of response separately
        if 200 > r.status_code >= 399:
            return RetVal(action_result.set_status(phantom.APP_ERROR, r.text), None)
        # Process a json response
        if 'xml' in r.headers.get('Content-Type', ''):
            return self._process_xml_response(r, action_result)

        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), message)

    def _login(self, action_result):
        """ Login to McAfee Web Gateway

        Args:
            action_result (ActionResult): Action Result

        Returns:
            str: Errors, if they exist

        """
        ret_val, response = self._make_rest_call('login', action_result, method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_message()

        self._session_id = response.get('entry', {}).get('content')

        return ''

    def _logout(self, action_result, commit=False):
        """ Commit changes and logout of McAfee Web Gateway

        Args:
            action_result (ActionResult): Action Result
            commit (bool): If True, attempt to send commit

        Returns:
            str: Errors, if they exist

        """
        message = ''
        if commit:
            ret_val, commit_response = self._make_rest_call('commit', action_result, method='post')
            if phantom.is_fail(ret_val):
                message += f'Unable to commit changes - Details: {commit_response}\n'

        ret_val, logout_response = self._make_rest_call('logout', action_result, method="post")
        if phantom.is_fail(ret_val):
            message += f'Could not destroy session {logout_response}'

        self._session_id = None

        return message

    def _make_rest_call(self, endpoint, action_result, headers=None, method='get', **kwargs):

        auth = None
        resp_json = None

        url = f'{self._base_url}{endpoint}'
        if not isinstance(headers, dict):
            headers = {}

        if endpoint == 'login':
            config = self.get_config()
            auth = (config['username'], config['password'])
        else:
            if not self._session_id:
                login_message = self._login(action_result)
                if not self._session_id:
                    return RetVal(action_result.set_status(phantom.APP_ERROR, f'Error logging in: {login_message}'), None)

            headers['Cookie'] = f'JSESSIONID={self._session_id}'
            if method == 'post':
                headers['Content-Type'] = 'application/xml'

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, f'Invalid method: {method}'), resp_json)

        try:
            r = request_func(
                url,
                auth=auth,
                headers=headers,
                verify=self._verify,
                **kwargs
            )
        except requests.exceptions.InvalidSchema:
            error_message = 'Error connecting to server. No connection adapters were found for %s' % (url)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except requests.exceptions.InvalidURL:
            error_message = 'Error connecting to server. Invalid URL %s' % (url)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except requests.exceptions.RequestException as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, err), None)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, err), resp_json)

        return self._process_response(r, action_result)

    # Utility functions #
    def _get_list_entries(self, list_data):
        list_entries = list_data.get('entry', {}).get('content', {}).get('list', {}).get('content', {}).get('listEntry', [])
        if not isinstance(list_entries, list):
            list_entries = [list_entries]
        return list_entries

    def _determine_entry_position(self, list_data, value):

        entry_position = None

        list_entries = self._get_list_entries(list_data)

        if 'complex' in list_data['entry']['id']:
            for position, complexEntry in enumerate(list_entries):
                for config in complexEntry['complexEntry']['configurationProperties']['configurationProperty']:
                    if config['@key'] in ['url', 'domain', 'ip'] and config['@value'] == value.lower():
                        entry_position = position
                        break
                if entry_position is not None:
                    break
        else:
            for position, entry in enumerate(list_entries):
                if entry['entry'].lower() == value.lower():
                    entry_position = position
                    break

        return entry_position

    def _get_lists(self, action_result, list_type='any'):
        """
        Get list of lists by the type provided.
        """

        params = {'pageSize': 100}
        if list_type != 'any':
            params['type'] = list_type

        ret_val, response = self._make_rest_call('list', action_result, method='get', params=params)

        if phantom.is_fail(ret_val):
            return RetVal(action_result.get_status(), None)

        page_finder = re.compile(r'(?<=page=)[0-9]+')

        pages = []

        if len(response['feed']['link']) > 1:
            for link in response['feed']['link']:
                page_num = page_finder.findall(link['@href'])
                page_num = list(set(page_num))
                if len(page_num) > 0 and int(page_num[0]) > 1:
                    pages.append(page_num[0])
            for page in pages:
                params['page'] = page
                ret_val, next_page = self._make_rest_call('list', action_result, method='get', params=params)
                if phantom.is_fail(ret_val):
                    return RetVal(action_result.set_status(phantom.APP_ERROR, 'Could not get lists.'), None)
                response['feed']['entry'] += next_page['feed']['entry']

        return RetVal(phantom.APP_SUCCESS, response)

    def _get_list(self, list_title, list_id, action_result):
        """
        Get list with list_id, if provided.
        Otherwise, get the list_id by using the list_title first, then get the list.
        """
        endpoint = 'list/'
        params = {}
        if not list_id:
            params['name'] = list_title
            ret_val, found_list_info = self._make_rest_call(endpoint, action_result, method='get', params=params)

            if phantom.is_fail(ret_val):
                self._logout(action_result)
                return RetVal(action_result.get_status(), None)

            list_id = found_list_info.get('feed', {}).get('entry', {}).get('id')

            if not list_id:
                self._logout(action_result)
                return RetVal(action_result.set_status(phantom.APP_ERROR, 'Could not find list by title.'), None)

        endpoint = f'{endpoint}{list_id}'

        ret_val, found_list_data = self._make_rest_call(endpoint, action_result, method='get', params=params)

        if phantom.is_fail(ret_val):
            self._logout(action_result)
            return RetVal(action_result.get_status(), None)

        return RetVal(phantom.APP_SUCCESS, found_list_data)

    # handle action functions #
    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress('Connecting to McAfee Web Gateway')

        # Get MWG version
        endpoint = 'version/mwg-ui'
        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            self.save_progress('Test Connectivity Failed.')
            self.save_progress(self._logout(action_result))
            return action_result.set_status(phantom.APP_ERROR, 'Unable to get McAfee Web Gateway version number.')

        self.save_progress('McAfee Web Gateway version: {0}'.format(response.get('entry', {}).get('content')))
        self.debug_print(f'JSESSIONID - {self._session_id}')

        # Logout of MWG
        logout_error = self._logout(action_result)
        if logout_error:
            return action_result.set_status(phantom.APP_ERROR, logout_error)

        self.save_progress('Test Connectivity Passed')
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_lists(self, param):

        self.save_progress(f'In action handler for: {self.get_action_identifier()}')

        action_result = self.add_action_result(ActionResult(dict(param)))

        list_type = param.get('type', 'any')

        lists_retrieved, lists = self._get_lists(action_result, list_type)
        if not lists_retrieved:
            self._logout(action_result)
            return action_result.get_status()

        list_entries = lists.get('feed', {}).get('entry', [])
        action_result.update_summary({'lists_found': len(list_entries)})

        for entry in list_entries:
            # Remove excess details
            with suppress(KeyError):
                del entry['link']
            action_result.add_data(entry)

        logout_error = self._logout(action_result)
        if logout_error:
            return action_result.set_status(phantom.APP_ERROR, logout_error)

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully returned lists')

    def _handle_get_list(self, param):

        self.save_progress(f'In action handler for: {self.get_action_identifier()}')

        action_result = self.add_action_result(ActionResult(dict(param)))

        if not (param.get('list_id') or param.get('list_title')):
            return action_result.set_status(phantom.APP_ERROR, 'A list_title or list_id must be supplied.')

        ret_val, found_list_data = self._get_list(param.get('list_title'), param.get('list_id'), action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Save list attributes to the summary and remove @ from attribute key names
        summary = action_result.update_summary(
            {k.lstrip('@'): v for k, v in found_list_data.get('entry', {}).get('content', {}).get('list', {}).items() if k != 'content'}
        )

        list_content = self._get_list_entries(found_list_data)
        summary['list_entries'] = len(list_content)
        if list_content:
            for position, entry in enumerate(list_content):
                entry['entry_position'] = position
                action_result.add_data(entry)

        logout_error = self._logout(action_result)
        if logout_error:
            return action_result.set_status(phantom.APP_ERROR, logout_error)

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully returned list')

    def _handle_add_entry(self, param):
        """ Handles all "block" actions

        Args:
            param (dict): Action parameters

        Returns:
            bool: APP_SUCCESS or APP_ERROR

        """

        action_id = self.get_action_identifier()
        self.save_progress(f'In action handler for: {action_id}')
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Process input parameters
        item_type = action_id.split('_')[-1]
        item = param.get(item_type)
        if not item:
            return action_result.set_status(phantom.APP_ERROR, f'Must provide {item_type} to run action.')

        description = param.get('description')
        list_id = param.get('list_id')
        list_title = param.get('list_title')
        entry_position = param.get('entry_position', 0)
        ret_val, entry_position = self._validate_integer(action_result, entry_position, ENTRY_POSITION_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        complex_entry = param.get('complex', False)
        protocol = param.get('protocol')
        category = param.get('category')

        if not (list_id or list_title):
            return action_result.set_status(phantom.APP_ERROR, 'A list_id or list_title must be provided.')

        # If list_id not provided, get it by using the list_title
        if list_title and not list_id:
            ret_val, list_data = self._get_list(list_title, None, action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            list_id = list_data.get('entry', {}).get('id')

        # Create entry XML
        if complex_entry:
            if not (category and protocol):
                message = 'When adding a "complex entry", category and protocol must be provided.'
                return action_result.set_status(phantom.APP_ERROR, message)

            config_type = 'com.scur.type.string'
            if item_type == 'ip':
                # Catches IP Ranges in either form: "0.0.0.0/30" or "0.0.0.0-1.0.0.0"
                if '/' in item or '-' in item:
                    config_type = 'com.scur.type.iprange'
                else:
                    config_type = 'com.scur.type.ip'

            entry = f'''<entry>
                <content>
                    <listEntry>
                        <complexEntry defaultRights="2">
                            <configurationProperties>
                                <configurationProperty key="protocol" type="com.scur.type.string" encrypted="false" value="{protocol}"/>
                                <configurationProperty key="{item_type}" type="{config_type}" encrypted="false" value="{item}"/>
                                <configurationProperty
                                    key="categories"
                                    type="com.scur.type.inlineList"
                                    listType="com.scur.type.category"
                                    encrypted="false"
                                    value="&lt;list version=&quot;1.0.3.46&quot;
                                        mwg-version=&quot;7.8.2-26361&quot;
                                        classifier=&quot;Other&quot;
                                        systemList=&quot;false&quot;
                                        structuralList=&quot;false&quot;
                                        defaultRights=&quot;2&quot;&gt;&#xa;
                                        &lt;description&gt;&lt;/description&gt;&#xa;
                                        &lt;content&gt;&#xa;
                                        &lt;listEntry&gt;&#xa;
                                        &lt;entry&gt;{category}&lt;/entry&gt;&#xa;
                                        &lt;description&gt;&lt;/description&gt;&#xa;
                                        &lt;/listEntry&gt;&#xa;
                                        &lt;/content&gt;&#xa;&lt;/list&gt;"/>
                            </configurationProperties>
                        </complexEntry>
                        <description>{description}</description>
                    </listEntry>
                </content>
            </entry>'''
        else:
            entry = f'''<entry xmlns="http://www.w3org/2011/Atom">
                <content type="application/xml">
                    <listEntry>
                        <entry>{item}</entry>
                        <description>{description}</description>
                    </listEntry>
                </content>
            </entry>'''

        # Send REST call to add entry
        endpoint = f'list/{list_id}/entry/{entry_position}/insert'
        ret_val, response = self._make_rest_call(endpoint, action_result, method='post', data=entry)
        if phantom.is_fail(ret_val):
            self._logout(action_result)
            existing_message = action_result.get_message()
            # Don't send error if the item already exists in the list
            if 'duplicate' in existing_message:
                message = f'"{item}" is already in the requested list'
                return action_result.set_status(phantom.APP_SUCCESS, message)
            else:
                message = f'Could not add entry to the list. Details - {existing_message}'
                return action_result.set_status(phantom.APP_ERROR, message)

        # Logout
        logout_error = self._logout(action_result, commit=True)
        if logout_error:
            return action_result.set_status(phantom.APP_ERROR, logout_error)

        # Process ActionResult
        with suppress(KeyError):
            del response['entry']['link']
        action_result.add_data(response)

        message = f'Successfully added {item_type} to list.'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_remove_entry(self, param):
        """ Handles all "unblock" actions

        Args:
            param (dict): Action parameters

        Returns:
            bool: APP_SUCCESS or APP_ERROR

        """

        action_id = self.get_action_identifier()
        self.save_progress(f'In action handler for: {action_id}')
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Process input parameters
        item_type = action_id.split('_')[-1]
        item = param.get(item_type)

        list_id = param.get('list_id')
        list_title = param.get('list_title')
        entry_position = param.get('entry_position', 0)
        ret_val, entry_position = self._validate_integer(action_result, entry_position, ENTRY_POSITION_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        list_data = None

        if not (list_id or list_title):
            return action_result.set_status(phantom.APP_ERROR, 'A list_id or list_title must be provided.')

        # If list_id not provided, get it by using the list_title
        if list_title and not list_id:
            ret_val, list_data = self._get_list(list_title, None, action_result)
            if phantom.is_fail(ret_val):
                self._logout(action_result)
                return action_result.get_status()
            list_id = list_data.get('entry', {}).get('id')

        if not (item or entry_position):
            return action_result.set_status(
                phantom.APP_ERROR,
                f'{item_type} or entry position most be provided. Use {item_type} if you are unsure of entry position to be removed.'
            )
        elif not entry_position and item:
            if not list_data:
                ret_val, list_data = self._get_list(list_title, list_id, action_result)
                if phantom.is_fail(ret_val):
                    self._logout(action_result)
                    return action_result.get_status()
                list_id = list_data.get('entry', {}).get('id')

            entry_position = self._determine_entry_position(list_data, item)
            if entry_position is None:
                message = 'Entry not found in list.'
                return action_result.set_status(phantom.APP_ERROR, message)

        # make rest call
        endpoint = f'list/{list_id}/entry/{entry_position}'
        ret_val, response = self._make_rest_call(endpoint, action_result, method='delete')
        if phantom.is_fail(ret_val):
            self._logout(action_result)
            existing_message = action_result.get_message()
            message = f'Could not remove entry from the list. Details - {existing_message}'
            return action_result.set_status(phantom.APP_ERROR, message)

        # Logout
        logout_error = self._logout(action_result, commit=True)
        if logout_error:
            return action_result.set_status(phantom.APP_ERROR, logout_error)

        # Process ActionResult
        with suppress(KeyError):
            del response['entry']['link']
        action_result.add_data(response)

        message = f'Successfully removed {item_type} from list.'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def handle_action(self, param):

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", action_id)

        supported_actions = {
            'test_connectivity': self._handle_test_connectivity,
            'list_lists': self._handle_list_lists,
            'get_list': self._handle_get_list,
            'add_entry': self._handle_add_entry,
            'remove_entry': self._handle_remove_entry,
            'block_url': self._handle_add_entry,
            'unblock_url': self._handle_remove_entry,
            'block_domain': self._handle_add_entry,
            'unblock_domain': self._handle_remove_entry,
            'block_ip': self._handle_add_entry,
            'unblock_ip': self._handle_remove_entry
        }

        if action_id in supported_actions:
            ret_val = supported_actions[action_id](param)
        else:
            raise ValueError('Action {0} is not supported'.format(action_id))

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()
        config = self.get_config()

        # Normalize base_url to first remove extra url paths if they exist and add them back.
        base_url = config['base_url']
        url_paths = ['/', 'Konfigurator', '/', 'REST', '/']
        for path in url_paths[::-1]:
            base_url = base_url.rstrip(path)
        self._base_url = f'{base_url}{"".join(url_paths)}'

        self._session_id = None
        self._verify = config.get('verify_server_cert', False)

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)

        if self._session_id:
            # Make sure to logout if not already done.
            requests.post(
                f'{self._base_url}logout',
                headers={'Cookie': f'JSESSIONID={self._session_id}', 'Content-Type': 'application/xml'},
                verify=self._verify
            )

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

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = McafeeWebGatewayConnector._get_phantom_base_url() + '/login'

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

        connector = McafeeWebGatewayConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
