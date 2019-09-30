# File: forcepointwebsecurity_connector.py
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
from collections import defaultdict


class ForcepointWebSecurityConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(ForcepointWebSecurityConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._port = None
        self._username = None
        self._password = None
        self._verify_cert = None

        self._transaction_id = None

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return phantom.APP_SUCCESS, {}

        return action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None

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
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return action_result.set_status(phantom.APP_ERROR, message), None

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return phantom.APP_SUCCESS, resp_json

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return action_result.set_status(phantom.APP_ERROR, message), None

    def _process_text_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = json.loads(r.text)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse text response as JSON. Error: {0}".format(str(e))), None

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return phantom.APP_SUCCESS, resp_json

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return action_result.set_status(phantom.APP_ERROR, message), None

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
        if 'text' in r.headers.get('Content-Type', ''):
            return self._process_text_response(r, action_result)

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
        message = "Can't process response from server. Status Code: {0} Content-Type: {1} Data from server: {1}".format(
                r.status_code, r.headers.get('Content-Type'), r.text.replace('{', '{{').replace('}', '}}'))

        return action_result.set_status(phantom.APP_ERROR, message), None

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get"):

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json

        # Create the URL for the REST call
        url = 'https://{}:{}/api/web/v1/{}'.format(self._base_url, self._port, endpoint)

        try:
            r = request_func(url,
                             auth=(self._username, self._password),  # basic authentication
                             json=data,
                             headers=headers,
                             verify=self._verify_cert,
                             params=params)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json

        return self._process_response(r, action_result)

    def _start_transaction(self, action_result):
        """ Initiate API write transactions with Forcepoint management API.

        Args:
            action_result (ActionResult): Action_result object for the current action

        Returns:
            ActionResult status: success/failure
            str: Transaction ID created by Forcepoint
        """
        self.save_progress('Attempting to start transaction...')
        ret_val, response = self._make_rest_call('categories/start', action_result, method='post')

        self.debug_print('Start transaction response', response)

        if phantom.is_fail(ret_val):
            message = 'Failed to start transaction. Error Response: {}. Error Message: {}'.format(response, action_result.get_message())
            return action_result.set_status(phantom.APP_ERROR, message), None

        if 'Transaction ID' in response:
            # Keep track of the Transaction ID to make sure it gets closed out if canceled.
            self.transaction_id = response['Transaction ID']
            return phantom.APP_SUCCESS, response['Transaction ID']

        message = 'Missing Transaction ID when starting transaction: {}'.format(response)
        return action_result.set_status(phantom.APP_ERROR, message), None

    def _commit_transaction(self, action_result, transaction_id):
        """ Commit changes that have been made during this transaction.

        Args:
            action_result (ActionResult): Action_result object for the current action
            transaction_id (str): ID of the Forcepoint transaction to commit

        Returns:
            ActionResult status: success/failure
            str: Commit time from Forcepoint
        """
        self.save_progress('Attempting to commit transaction...')
        params = {'transactionid': transaction_id}

        ret_val, response = self._make_rest_call('categories/commit', action_result, params=params, method='post')

        self.debug_print('Commit transaction response', response)

        if phantom.is_fail(ret_val):
            message = 'Failed to commit transaction. Error Response: {}. Error Message: {}'.format(response, action_result.get_message())
            return action_result.set_status(phantom.APP_ERROR, message), None

        # Expect 'Commit Time' in the response
        if 'Commit Time' in response:
            self.transaction_id = None
            return phantom.APP_SUCCESS, response['Commit Time']

        message = 'Missing "Commit Time" when attempting to commit transaction: {}'.format(response)
        return action_result.set_status(phantom.APP_ERROR, message), None

    def _rollback_transaction(self, action_result, transaction_id):
        """ Rollback changes that have been made during this transaction. Used for canceling an action that may have already begun.

        Args:
            action_result (ActionResult): Action_result object for the current action
            transaction_id (str): ID of the Forcepoint transaction to rollback

        Returns:
            ActionResult status: success/failure
            str: Rollback time from Forcepoint
        """
        self.save_progress('Attempting to rollback transaction...')

        if not transaction_id:
            # If transaction_id doesn't exist, return the latest status
            self.append_to_message('\nUnable to rollback due to not having a "Transaction ID", most likely not started.')
            return None

        params = {'transactionid': transaction_id}

        ret_val, response = self._make_rest_call('categories/rollback', action_result, params=params, method='post')

        self.debug_print('Rollback transaction response', response)

        if phantom.is_fail(ret_val):
            message = 'Failed to rollback transaction. Error Response: {}. Error Message: {}'.format(response, action_result.get_message())
            self.append_to_message(message)
            return None

        # Expect 'Rollback Time' in the response
        if 'Rollback Time' in response:
            self.transaction_id = None
            self.append_to_message('Successfully rolled back transaction.')
            return response['Rollback Time']

        self.append_to_message('Missing "Rollback Time" when attempting to cancel transaction: {}'.format(response))
        return None

    def _get_categories(self, action_result):
        """ Get API-managed categories using the Forcepoint API.

        Args:
            action_result (ActionResult): Action_result object for the current action

        Returns:
            ActionResult status: success/failure
            dict: Category list returned from Forcepoint
        """
        self.save_progress('Getting list of current categories...')
        ret_val, response = self._make_rest_call('categories', action_result)

        self.debug_print('Category list response', response)

        if phantom.is_fail(ret_val):
            message = "Failed to fetch 'Categories' from the response while trying to get the list of categories."
            message += ' Error Response: {}. Error Message: {}'.format(response, action_result.get_message())
            return action_result.set_status(phantom.APP_ERROR, message), None

        # Expect 'Categories' in the response
        if 'Categories' in response:
            return phantom.APP_SUCCESS, response

        message = 'Missing "Categories" from the response while trying to get the list of categories: {}'.format(response)
        return action_result.set_status(phantom.APP_ERROR, message), None

    def _get_category_contents(self, action_result, category_name=None, category_id=None):
        """ Return contents of a category using the Forcepoint API.

        Args:
            action_result (ActionResult): Action_result object for the current action
            category_name (str, optional if category_id exists): Name of category to lookup, will use name if both are provided
            category_id (str, optional if category_name exists): ID of category to lookup

        Returns:
            dict: JSON response including the contents of the container
        """
        self.save_progress('Getting category contents...')
        if category_name:
            params = {'catname': category_name}
        elif category_id:
            params = {'catid': category_id}
        else:
            message = 'Either "category_name" or "category_id" are required to request the category'
            return action_result.set_status(phantom.APP_ERROR, message), None

        return self._make_rest_call('categories/urls', action_result, params=params)

    def _create_category(self, action_result, transaction_id, category_name, description=None, parent_id=0):
        """ Create category using the Forcepoint API to be used as a container for IPs and URLs.

        Args:
            action_result (ActionResult): Action_result object for the current action
            transaction_id (str): Transaction ID to use for tracking changes on Forcepoint
            category_name (str): Name of new category, must be unique to the current Forcepoint categories
            description (str, optional): Description of the new category, blank if not provided.
            parent_id (int, optional): ID of the parent, will be set as 0 (top-level) if not provided.

        Returns:
            ActionResult status: success/failure
            dict: response from Forcepoint
        """
        self.save_progress('Creating category...')
        data = {
            'Transaction ID': transaction_id,
            'Categories': [
                {
                    'Category Name': category_name,
                    'Parent': parent_id
                }
            ]
        }

        if description:
            data['Categories'][0]['Category Description'] = description

        self.debug_print('Creating category request', data)

        ret_val, response = self._make_rest_call('categories', action_result, data=data, method='post')
        if phantom.is_fail(ret_val):
            message = 'Failed to create category. Error Response: {}. Error Message: {}'.format(response, action_result.get_message())
            return action_result.set_status(phantom.APP_ERROR, message), None

        return phantom.APP_SUCCESS, response

    def _flatten_categories(self, categories):
        """ Recursively flatten the category list from 'Children' in a category.

        The Forcepoint API returns categories in a tiered view, if categories are added as children to other categories. This method
        returns an un-tiered category list to be able to easily iterate over.

        Args:
            categories (list of dict): Category list returned from Forcepoint

        Returns:
            list: A flat list of dicts containing category details.
        """
        cat_list = []

        if isinstance(categories, list):  # Check if categories is a list.
            for category in categories:
                if isinstance(category, dict):  # Check if category is a dict.
                    children = category.pop('Children', None)
                    # Add to cat_list without children
                    cat_list.append(category)

                    # If children exist in this category, go through and add them separately.
                    if children:
                        result = self._category_lookup(children)
                        if result:
                            cat_list.extend(result)
        return cat_list

    def _lookup_objects(self, action_result, objects):
        """ With a list of objects (IPs and/or URLs), return a dictionary where the keys are the
            object and the value is a list of category names that contain that object.

        Args:
            action_result (ActionResult): Action_result object for the current action
            objects (list): List of IPs or URLs to lookup

        Returns:

            dict: Map of objects and the categories that include them.
        """

        # Get list of categories
        ret_val, categories = self._get_categories(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        # Flatten categories to not show hierarchy
        flat_categories = self._flatten_categories(categories['Categories'])

        # Create a map of IPs/ URLs to Category Names to return
        category_map = {obj: [] for obj in objects}
        for category in flat_categories:
            ret_val, cat_details = self._get_category_contents(action_result, category['Category Name'])
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            # Go through each IP and URL in a category and check to see if it exists
            for curr_obj_type in ['IPs', 'URLs']:
                for curr_obj in cat_details[curr_obj_type]:
                    # Because URLs may or may not include the protocol from the input parameter, check if either match
                    if curr_obj in category_map.keys():
                        category_map[curr_obj].append(category['Category Name'])
                        break
                    elif curr_obj.split('//')[-1] in category_map.keys():
                        category_map[curr_obj.split('//')[-1]].append(category['Category Name'])
                        break

        return phantom.APP_SUCCESS, category_map

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress('Connecting to endpoint')
        # make rest call to the status endpoint
        ret_val, response = self._make_rest_call('categories/status', action_result)

        if phantom.is_fail(ret_val):
            # The call failed. Return status and error returned.
            self.save_progress('Test connectivity failed: {}'.format(response))
            return action_result.get_status()

        self.save_progress('Test connectivity passed')
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_block_objects(self, param):
        """ Block IPs or URLs sent in by adding it to an API-managed category in Forcepoint and build action_results.

        Args:
            param (dict): Action parameters

        Returns:
            ActionResult status: success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary = action_result.update_summary({})

        # Get params
        payload = {}
        if 'ip' in param:
            payload['IPs'] = [ip.strip() for ip in param['ip'].split(',')]
        if 'url' in param:
            payload['URLs'] = [url.strip() for url in param['url'].split(',')]

        cat = param['category']
        payload['Category Name'] = cat

        create_cat = param.get('create_category', False)
        create_new_category = False

        # First, check to see if the category exists
        ret_val, categories = self._get_categories(action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if cat.lower() not in [category['Category Name'].lower() for category in self._flatten_categories(categories['Categories'])]:
            if not create_cat:
                # Asked to not create category, attempt rollback and return error
                message = 'Category "{}" does not exist. Create the category or enable the "create_category" option on this action and try again'.format(cat)
                return action_result.set_status(phantom.APP_ERROR, message)
            else:
                # Set boolean to create a category when the transaction has been started.
                create_new_category = True

        # Start transaction
        ret_val, transaction_id = self._start_transaction(action_result)
        if phantom.is_fail(ret_val):
            # Starting transaction failed, no rollback is required
            return action_result.get_status()
        payload['Transaction ID'] = transaction_id
        summary['transaction_id'] = transaction_id

        # Create new category first, if needed
        if create_new_category:
            ret_val, create_response = self._create_category(action_result, transaction_id, cat, 'Auto-generated category from Phantom')
            if phantom.is_fail(ret_val):
                # Creating container failed, attempt rollback and return error
                ret_val, rollback_time = self._rollback_transaction(action_result, transaction_id)
                summary['rollback_time'] = rollback_time

                return action_result.get_status()
            summary['created_category'] = True

        # Add objects to an existing category
        summary['category'] = cat
        self.debug_print('adding to category', payload)

        ret_val, add_obj_response = self._make_rest_call('categories/urls', action_result, data=payload, method='post')
        if phantom.is_fail(ret_val):
            # Adding IPs or URLs to a container failed, attempt rollback and return error
            ret_val, rollback_time = self._rollback_transaction(action_result, transaction_id)
            summary['rollback_time'] = rollback_time
            return action_result.get_status()

        # Commit transaction
        ret_val, commit_response = self._commit_transaction(action_result, transaction_id)
        if phantom.is_fail(ret_val):
            # Commit failed, attempt rollback and return error
            ret_val, rollback_time = self._rollback_transaction(action_result, transaction_id)
            summary['rollback_time'] = rollback_time
            return action_result.get_status()

        action_result.add_data(add_obj_response)

        message = "Successfully blocked IPs/URLs"
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_unblock_object(self, param):
        """ Unblock IPs or URLs sent in by removing it from a single API-managed category
        or all API-managed categories that contain it in Forcepoint and build action_results.

        Args:
            param (dict): Action parameters

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary = action_result.update_summary({})

        # Get params
        payload = {}
        if 'ip' in param:
            payload['IPs'] = [ip.strip() for ip in param['ip'].split(',')]
        if 'url' in param:
            payload['URLs'] = []
            for url in [url.strip() for url in param['url'].split(',')]:
                if '://' in url:
                    # If the protocol is included in the url, add it to the list of urls
                    payload['URLs'].append(url)
                else:
                    # If the protocol is not included, add each protocol that is automatically added supported by Forcepoint
                    for protocol in ['http', 'https', 'ftp']:
                        payload['URLs'].append('{}://{}'.format(protocol, url))

        category = param.get('category')

        # Transform the params to be a list of payloads based on the input
        if category:
            payload['Category Name'] = category
            payloads = [payload]
        else:
            ips = payload.get('IPs', [])
            urls = payload.get('URLs', [])
            ret_val, obj_to_cat = self._lookup_objects(action_result, ips + urls)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            # Invert 'object to category' mapping to have categories mapped to objects instead
            cat_to_obj = defaultdict(list)
            for obj, cats in obj_to_cat.iteritems():
                for cat in cats:
                    cat_to_obj[cat].append(obj)

            # Create payloads
            payloads = []
            for cat, objs in cat_to_obj.iteritems():
                payload = defaultdict(list, {'Category Name': cat})
                for obj in objs:
                    if obj in ips:
                        payload['IPs'].append(obj)
                    elif obj in urls:
                        payload['URLs'].append(obj)
                payloads.append(payload)

        if not payloads:
            message = 'IP(s) or URL(s) supplied were not found in any categories'
            return action_result.set_status(phantom.APP_SUCCESS, message)

        # Start transaction
        ret_val, transaction_id = self._start_transaction(action_result)
        if phantom.is_fail(ret_val):
            # Starting transaction failed, no rollback is required
            return action_result.get_status()
        summary['transaction_id'] = transaction_id

        # Send a delete request for each category that was submitted
        count_failures = 0
        for payload in payloads:
            payload['Transaction ID'] = transaction_id
            ret_val, response = self._make_rest_call('categories/delete/urls', action_result, data=payload, method='post')
            if phantom.is_fail(ret_val):
                response['failed_to_delete'] = True
                count_failures += 1
                # If all deletions failed, rollback transaction
                if count_failures == len(payloads):
                    # Deleting objects failed, attempt rollback and return error
                    ret_val, rollback_time = self._rollback_transaction(action_result, transaction_id)
                    summary['rollback_time'] = rollback_time
                    return action_result.get_status()
            response.update(payload)
            action_result.add_data(response)

        # Commit transaction
        ret_val, commit_time = self._commit_transaction(action_result, transaction_id)
        if phantom.is_fail(ret_val):
            # Committing transaction failed, attempt rollback and return error
            ret_val, rollback_time = self._rollback_transaction(action_result, transaction_id)
            summary['rollback_time'] = rollback_time
            return action_result.get_status()
        summary['commit_time'] = commit_time

        message = "Successfully blocked IPs/URLs"
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_lookup_object(self, param):
        """ List all of the categories that have the object in that container to build action_results.

        Args:
            param (dict): Action parameters

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # 'ip' or 'url' can be a single object or multiple objects if comma separated
        if 'ip' in param:
            obj_type = 'ip'
            object_list = [ip.strip() for ip in param['ip'].split(',')]
        elif 'url' in param:
            obj_type = 'url'
            object_list = [url.strip() for url in param['url'].split(',')]
        else:
            message = 'Missing required parameters (IP or URL): {}'.format(param)
            return action_result.set_status(phantom.APP_ERROR, message)

        ret_val, category_map = self._lookup_objects(action_result, object_list)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Separate each object into their own data result
        # Each object can be 'ip' or 'url'
        for obj, categories in category_map.iteritems():
            action_result.add_data({obj_type: obj, 'categories': categories})

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['lookup count'] = len(category_map)
        summary['found category count'] = len([v for v in category_map.itervalues() if v])

        message = 'Retrieved categories for each object: {}'.format(object_list)
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_get_category(self, param):
        """ Return IPs and URLs in a category to build action_results.

        Args:
            param (dict): Action parameters

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        summary = action_result.update_summary({})

        cat = param['category']

        ret_val, response = self._get_category_contents(action_result, cat)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        summary['category_name'] = response.get('Category Name')
        summary['category_id'] = response.get('Category ID')

        for obj in response.get('IPs', []):
            action_result.add_data({'ip': obj})

        for obj in response.get('URLs', []):
            action_result.add_data({'url': obj})

        message = 'Retrieved contents of category: {}'.format(cat)
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_list_categories(self, param):
        """ Return IPs and URLs in a category to build action_results.

        Args:
            param (dict): Action parameters

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        summary = action_result.update_summary({})

        ret_val, response = self._get_categories(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        categories = self._flatten_categories(response['Categories'])
        for category in categories:
            action_result.add_data(category)

        summary['category count'] = len(categories)

        message = 'Retrieved list of categories'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_delete_category(self, param):
        """ Delete an API-managed category in Forcepoint and build action_results.

        Args:
            param (dict): Action parameters

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        summary = action_result.update_summary({})

        cat = param['category']

        # Start transaction
        ret_val, transaction_id = self._start_transaction(action_result)
        if phantom.is_fail(ret_val):
            # Starting transaction failed, no rollback is required
            return action_result.get_status()
        summary['transaction_id'] = transaction_id

        payload = {
            'Category Names': [cat],
            'Transaction ID': transaction_id
        }

        # Delete category
        ret_val, response = self._make_rest_call('categories/delete', action_result, data=payload, method='post')
        if phantom.is_fail(ret_val):
            # Deleting category failed, attempt rollback and return error
            ret_val, rollback_time = self._rollback_transaction(action_result, transaction_id)
            summary['rollback_time'] = rollback_time
            return action_result.set_status(phantom.APP_ERROR, response)

        # Commit changes
        ret_val, commit_time = self._commit_transaction(action_result, transaction_id)
        if phantom.is_fail(ret_val):
            # Commit failed, attempt rollback and return error
            ret_val, rollback_time = self._rollback_transaction(action_result, transaction_id)
            summary['rollback_time'] = rollback_time
            return action_result.get_status()
        summary['commit_time'] = commit_time

        action_result.add_data({'category': cat})

        message = 'Category deleted: {}'.format(cat)
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_add_category(self, param):
        """ Add an API-managed category in Forcepoint and build action_results.

        Args:
            param (dict): Action parameters

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        summary = action_result.update_summary({})

        cat = param['category']
        desc = param.get('description')

        # Start transaction
        ret_val, transaction_id = self._start_transaction(action_result)
        if phantom.is_fail(ret_val):
            # Starting transaction failed, no rollback is required
            return action_result.get_status()
        summary['transaction_id'] = transaction_id

        # Create Category
        ret_val, response = self._create_category(action_result, transaction_id, cat, desc)
        if phantom.is_fail(ret_val):
            # Adding category failed, attempt rollback and return error
            ret_val, rollback_time = self._rollback_transaction(action_result, transaction_id)
            summary['rollback_time'] = rollback_time
            return action_result.get_status()
        action_result.add_data(response)

        # Commit changes
        ret_val, commit_time = self._commit_transaction(action_result, transaction_id)
        if phantom.is_fail(ret_val):
            # Commit failed, attempt rollback and return error
            ret_val, rollback_time = self._rollback_transaction(action_result, transaction_id)
            summary['rollback_time'] = rollback_time
            return action_result.get_status()
        summary['commit_time'] = commit_time

        message = 'Added category: {}'.format(cat)
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def handle_action(self, param):

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        supported_actions = {
            'test_connectivity': self._handle_test_connectivity,
            'block_ip': self._handle_block_objects,
            'block_url': self._handle_block_objects,
            'unblock_ip': self._handle_unblock_object,
            'unblock_url': self._handle_unblock_object,
            'lookup_ip': self._handle_lookup_object,
            'lookup_url': self._handle_lookup_object,
            'get_category': self._handle_get_category,
            'list_categories': self._handle_list_categories,
            'delete_category': self._handle_delete_category,
            'add_category': self._handle_add_category
        }

        if action_id in supported_actions:
            ret_val = supported_actions[action_id](param)
        else:
            raise ValueError('Action {0} is not supported'.format(action_id))

        return ret_val

    '''
    def handle_cancel(self):
        """ Is run when a user initiates a cancel during an action.
        Cancel the current action and send debug messages.
        """

        action_result = self.get_action_results()[0]

        if self._transaction_id:
            self._rollback_transaction(action_result, self._transaction_id)
        else:
            self.debug_print('Transaction ID is missing, the action may have not begun or was already complete.')
    '''

    def initialize(self):

        # get the asset config
        config = self.get_config()

        self._base_url = config['base_url'].encode('utf-8')
        self._port = config['port']
        self._username = config['username'].encode('utf-8')
        self._password = config['password']

        self._verify_cert = config.get('verify_server_certificate', False)

        return phantom.APP_SUCCESS

    def finalize(self):

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
            login_url = BaseConnector._get_phantom_base_url() + "login"
            print ("Accessing the Login page")
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
            print ("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ForcepointWebSecurityConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
