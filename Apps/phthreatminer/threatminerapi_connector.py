# Copyright (c) 2019 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from threatminerapi_consts import *
import requests
import json
import time
import ipaddress
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class ThreatminerApiConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(ThreatminerApiConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _is_ip(self, input_ip_address):
        """ Function that checks given address and return True if address is valid IPv4 or IPV6 address.

        :param input_ip_address: IP address
        :return: status (success/failure)
        """

        ip_address_input = input_ip_address

        try:
            ipaddress.ip_address(unicode(ip_address_input))
        except:
            return False

        return True

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

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

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get"):

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = '{0}{1}'.format(self._base_url, endpoint)

        try:
            r = request_func(
                            url,
                            # auth=(username, password),  # basic authentication
                            data=data,
                            headers=headers,
                            verify=config.get('verify_server_cert', False),
                            params=params)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Create a new Threat Miner Python Object
        endpoint = 'domain.php?q=vwrm.com&rt=1'

        # Make test connection to the test connectivity endpoint
        ret_val, response = self._make_rest_call(endpoint, action_result)

        # Connect to Phantom Endpoint
        self.save_progress("Connecting to endpoint")

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            self.save_progress("Test Connectivity Failed")
            message = "Test Connectivity Failed"
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_domain(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access the domain parameter
        domain = param['domain']

        # Create a new Threat Miner Python Object
        endpoint = 'domain.php?q={}&rt={}'.format(domain, 2)

        # Issue request to get_domain function
        ret_val, response = self._make_rest_call(endpoint, action_result)

        # If the result fails
        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            message = ("Lookup Domain at endpoint: {} "
                        "request received a non 200 response".format(endpoint))
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        # Create new python dictionary to store output
        data_output = response

        # Add the response into the data section
        action_result.add_data(data_output)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['domain'] = domain
        summary['status_message'] = data_output['status_message']

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_hash(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access Hash parameter
        hash_value = param['hash']

        # Access Hash Type
        hash_type = param['hash_type']

        if hash_type not in["cryptographic_hash", "ssdeep", "imphash"]:
            message = ('Invalid hash type, acceptable values ["cryptographic_hash", "ssdeep", "imphash"]')
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        # List the available functions that the hash function provides in the threatMiner API
        crypto_hash_functions = {
            1: "metadata",
            2: "http_traffic",
            3: "hosts_domains_and_ips",
            4: "mutants",
            5: "registry_keys",
            6: "av_detections",
            7: "report_tagging"
        }

        # List the available functions that the fuzzy hashing provides in the threatMiner API
        fuzzy_hash_functions = {
            1: "samples",
            2: "report_tagging"
        }

        # Create an empty dictionary for pushing results into the
        result_dictionary = {}

        # If the hash type is a cryptographic hash
        if hash_type == "cryptographic_hash":
            self.save_progress("Cryptographic hash selected")
            # Iterate through the functions
            for i in range(1, 8):
                # Make the API call
                endpoint = 'sample.php?q={}&rt={}'.format(hash_value, i)

                # Issue request to get_domain function
                ret_val, response = self._make_rest_call(endpoint, action_result)

                # Notify user that the request is progressing
                self.save_progress("Issuing {} request at endpoint: {}".format(i, endpoint))

                if (phantom.is_fail(ret_val)):
                    # the call to the 3rd party device or service failed, action result should contain all the error details
                    # so just return from here
                    message = ("Lookup ssdeep at endpoint: {} "
                             "request received a non 200 response".format(endpoint))
                    return action_result.set_status(phantom.APP_ERROR, status_message=message)

                # If the call is successfull
                if int(response['status_code']) == 200:
                    self.save_progress("Received 200 OK from ThreatMiner")
                    # Output the results to a dictionary
                    result_dictionary[crypto_hash_functions[i]] = response
                # If the call fails
                else:
                    # Output none to the result_dictionary for the
                    result_dictionary[crypto_hash_functions[i]] = None

                # Notify user that the command is sleeping
                self.save_progress("Sleeping 8 seconds to avoid API throttling")
                # Throttle communication to ensure we do not go over 10 requests per minute.
                time.sleep(8)

            # Check to see if all the requests result in a not found response
            complete_result = all(result_dictionary[crypto_hash_functions[i]] is None for i in range(1, 8))

        # If the hash type is a ssdeep hash
        elif hash_type == "ssdeep":
            self.save_progress("ssdeep hash selected")
            # Iterate through the functions
            for i in range(1, 3):
                # If the call is successfull
                # Make the API call
                endpoint = 'ssdeep.php?q={}&rt={}'.format(hash_value, i)

                # Issue request to SSDEEP function
                ret_val, response = self._make_rest_call(endpoint, action_result)

                # Notify user that the request is progressing
                self.save_progress("Issuing {} request at endpoint: {}".format(i, endpoint))

                if (phantom.is_fail(ret_val)):
                    # the call to the 3rd party device or service failed, action result should contain all the error details
                    # so just return from here
                    message = ("Lookup ssdeep at endpoint: {} "
                             "request received "
                             "a non 200 response".format(endpoint))
                    self.save_progress(message)
                    return action_result.get_status()
                # If the call is successfull
                if int(response['status_code']) == 200:
                    self.save_progress("Received 200 OK from ThreatMiner")
                    # Output the results to a dictionary
                    result_dictionary[fuzzy_hash_functions[i]] = response
                # If the call fails
                else:
                    # Output none to the result_dictionary for the
                    result_dictionary[fuzzy_hash_functions[i]] = None

                # Notify user that the command is sleeping
                self.save_progress("Sleeping 8 seconds to avoid API throttling")
                # Throttle communication to ensure we do not go over 10 requests per minute.
                time.sleep(8)

            # Check to see if all the requests result in a not found response
            complete_result = all(result_dictionary[fuzzy_hash_functions[i]] is None for i in range(1, 3))

        # If the hash type is a imphash
        elif hash_type == "imphash":
            self.save_progress("imphash selected")
            # Iterate through the functions
            for i in range(1, 3):
                # Make the API call
                endpoint = 'imphash.php?q={}&rt={}'.format(hash_value, i)

                # Issue request to SSDEEP function
                ret_val, response = self._make_rest_call(endpoint, action_result)

                # Notify user that the request is progressing
                self.save_progress("Issuing {} request at endpoint: {}".format(i, endpoint))

                if (phantom.is_fail(ret_val)):
                    # the call to the 3rd party device or service failed, action result should contain all the error details
                    # so just return from here
                    message = ("Lookup imphash at endpoint: {} "
                             "request received"
                             "a non 200 response".format(endpoint))
                    return action_result.set_status(phantom.APP_ERROR, status_message=message)
                # If the call is successfull
                if int(response['status_code']) == 200:
                    self.save_progress("Received 200 OK from ThreatMiner")
                    # Output the results to a dictionary
                    result_dictionary[fuzzy_hash_functions[i]] = response
                # If the call fails
                else:
                    # Output none to the result_dictionary for the
                    result_dictionary[fuzzy_hash_functions[i]] = None

                # Notify user that the command is sleeping
                self.save_progress("Sleeping 8 seconds to avoid API throttling")
                # Throttle communication to ensure we do not go over 10 requests per minute.
                time.sleep(8)

            # Check to see if all the requests result in a not found response
            complete_result = all(result_dictionary[fuzzy_hash_functions[i]] is None for i in range(1, 3))

        # Create new python dictionary to store output
        data_output = result_dictionary

        # Add the response into the data section
        action_result.add_data(data_output)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['hash'] = hash_value

        # If all of the results are None (No records found), update the summary message
        if complete_result:
            summary['status_message'] = "No results found"
        # Else add the output of the status message
        else:
            summary['status_message'] = "Results found"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_ip(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access the ip parameter for passing into Phantom
        ip = param['ip']

        ip_lookup_functions = {
            3: "uris",
            4: "related_samples",
            5: "ssl_certificates",
            6: "report_tagging"
        }

        # Create an empty dictionary for pushing results into the
        result_dictionary = {}

        # Iterate through the functions
        for i in range(3, 7):
            # Build the API call URL
            endpoint = 'host.php?q={}&rt={}'.format(ip, i)
            # Make the API call
            ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

            if (phantom.is_fail(ret_val)):
                    # the call to the 3rd party device or service failed, action result should contain all the error details
                    # so just return from here
                    message = ("Lookup IP at endpoint: {} "
                             "request received a non 200 response".format(endpoint))
                    return action_result.set_status(phantom.APP_ERROR, status_message=message)
            # If the call is successfull
            if int(response['status_code']) == 200:
                # Output the results to a dictionary
                result_dictionary[ip_lookup_functions[i]] = response
                self.save_progress("Data found for lookup to"
                                   " threatminer API: "
                                   "{}".format(ip_lookup_functions[i]))
            # If the call fails
            else:
                # Output none to the result_dictionary for the
                result_dictionary[ip_lookup_functions[i]] = None
                self.save_progress("No data found for lookup to"
                                   " threatminer API: "
                                   "{}".format(ip_lookup_functions[i]))

                # Notify user that the command is sleeping
                self.save_progress("Sleeping 8 seconds to avoid API throttling")
                # Throttle communication to ensure we do not go over 10 requests per minute.
                time.sleep(8)

        # Check to see if all the requests result in a not found response
        complete_result = all(result_dictionary[ip_lookup_functions[i]] is None for i in range(3, 7))

        # Create new python dictionary to store output
        data_output = result_dictionary

        # Add the response into the data section
        action_result.add_data(data_output)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['ip'] = ip

        # If all of the results are None (No records found), update the summary message
        if complete_result:
            summary['status_message'] = "No results found"
        # Else add the output of the status message
        else:
            summary['status_message'] = "Results found"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_whois_domain(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access the ip parameter for passing into Phantom
        domain = param['domain']

        # URL that we are querying
        endpoint = 'domain.php?q={}&rt=1'.format(domain)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        # If the result fails
        if (phantom.is_fail(ret_val)):
                    # the call to the 3rd party device or service failed, action result should contain all the error details
                    # so just return from here
                    message = ("Lookup IP at endpoint: {} "
                             "request received a non 200 response".format(endpoint))
                    return action_result.set_status(phantom.APP_ERROR, status_message=message)

        # If the call is successfull
        if int(response['status_code']) == 200:
            # Output the results to a dictionary
            self.save_progress("Data found for lookup to"
                               " threatminer API: Whois Domain")
        # If the call fails
        else:
            self.save_progress("No Data found for lookup to"
                               " threatminer API: Whois Domain")
        # Create new python dictionary to store output
        data_output = response

        # Add the response into the data section
        action_result.add_data(data_output)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['domain'] = domain
        summary['status_message'] = data_output['status_message']

        # Throttle the API call to avoid abusing the endpoint
        time.sleep(8)
        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_reverse_ip(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access the ip parameter for passing into Phantom
        ip = param['ip']

        # URL that we are querying
        endpoint = 'host.php?q={}&rt=2'.format(ip)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        # If the result fails
        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            message = ("Lookup IP at endpoint: {} "
                        "request received a non 200 response".format(endpoint))
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        # If the call is successfull
        if int(response['status_code']) == 200:
            # Output the results to a dictionary
            self.save_progress("Data found for lookup to"
                               " threatminer API: Reverse IP")

        # If the call fails
        else:
            self.save_progress("No Data found for lookup to"
                               " threatminer API: Reverse IP")
        # Create new python dictionary to store output
        data_output = response

        # Add the response into the data section
        action_result.add_data(data_output)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['domain'] = ip
        summary['status_message'] = data_output['status_message']

        # Throttle the API call to avoid abusing the endpoint
        time.sleep(8)
        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_whois_ip(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access the ip parameter for passing into Phantom
        ip = param['ip']

        # URL that we are querying
        endpoint = 'host.php?q={}&rt=1'.format(ip)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        # If the result fails
        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            message = ("Lookup IP at endpoint: {} "
                        "request received a non 200 response".format(endpoint))
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        # If the call is successfull
        if int(response['status_code']) == 200:
            # Output the results to a dictionary
            self.save_progress("Data found for lookup to"
                               " threatminer API: WHOIS IP")

        # If the call fails
        else:
            self.save_progress("No Data found for lookup to"
                               " threatminer API: WHOIS IP")
        # Create new python dictionary to store output
        data_output = response

        # Add the response into the data section
        action_result.add_data(data_output)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['domain'] = ip
        summary['status_message'] = data_output['status_message']

        # Throttle the API call to avoid abusing the endpoint
        time.sleep(8)
        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_av(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access the ip parameter for passing into Phantom
        av = param['av_string']

        av_lookup_functions = {
            1: "samples",
            2: "report_tagging"
        }

        # Create an empty dictionary for pushing results into the
        result_dictionary = {}

        # Iterate through the functions
        for i in range(1, 3):
            # Build the API call URL
            endpoint = 'av.php?q={}&rt={}'.format(av, i)
            # Make the API call
            ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

            if (phantom.is_fail(ret_val)):
                    # the call to the 3rd party device or service failed, action result should contain all the error details
                    # so just return from here
                    message = ("Lookup AV String at endpoint: {} "
                             "request received a non 200 response".format(endpoint))
                    return action_result.set_status(phantom.APP_ERROR, status_message=message)
            # If the call is successfull
            if int(response['status_code']) == 200:
                # Output the results to a dictionary
                result_dictionary[av_lookup_functions[i]] = response
                self.save_progress("Data found for lookup to"
                                   " threatminer API: "
                                   "{}".format(av_lookup_functions[i]))
            # If the call fails
            else:
                # Output none to the result_dictionary for the
                result_dictionary[av_lookup_functions[i]] = None
                self.save_progress("No data found for lookup to"
                                   " threatminer API: "
                                   "{}".format(av_lookup_functions[i]))
            # Throttle communication to ensure we do not go over 10 requests per minute.
            time.sleep(8)
        # Create empty file array
        file_hash_arr = []

        if result_dictionary['samples']:
            if result_dictionary['samples']['results']:
                # Append file_hash to
                for a in result_dictionary['samples']['results']:
                    file_hash_arr.append({"file_hash": a})
                result_dictionary['samples']['results'] = file_hash_arr

        # Check to see if all the requests result in a not found response
        complete_result = all(result_dictionary[av_lookup_functions[i]] is None for i in range(1, 3))

        # Create new python dictionary to store output
        data_output = result_dictionary

        # Add the response into the data section
        action_result.add_data(data_output)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['av_string'] = av

        # If all of the results are None (No records found), update the summary message
        if complete_result:
            summary['status_message'] = "No results found"
        # Else add the output of the status message
        else:
            summary['status_message'] = "Results found"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_ssl(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access the ip parameter for passing into Phantom
        thumbprint = param['thumbprint']

        # URL that we are querying
        endpoint = 'ssl.php?q={}&rt=1'.format(thumbprint)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        # If the result fails
        if (phantom.is_fail(ret_val)):
                    # the call to the 3rd party device or service failed, action result should contain all the error details
                    # so just return from here
                    message = ("Lookup SSL at endpoint: {} "
                             "request received a non 200 response".format(endpoint))
                    return action_result.set_status(phantom.APP_ERROR, status_message=message)

        # If the call is successfull
        if int(response['status_code']) == 200:
            # Output the results to a dictionary
            self.save_progress("Data found for lookup to"
                               " threatminer API: SSL")
            summary_message = response['status_message']
            # Creat an empty array for IP Addresses
            ip_arr = []
            # Iterate through each of the IP results
            for ip in response['results']:
                # Append each IP to the new array
                ip_arr.append({"ip": ip})

            # Add the ip_arr to the results json dict
            response['results'] = ip_arr

        # If the call fails
        else:
            self.save_progress("No Data found for lookup to"
                               " threatminer API: SSL")
            summary_message = "No results found"

        # Create new python dictionary to store output
        data_output = response

        # Add the response into the data section
        action_result.add_data(data_output)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['thumbprint'] = thumbprint
        summary['status_message'] = summary_message

        # Throttle the API call to avoid abusing the endpoint
        time.sleep(8)
        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'lookup_domain':
            ret_val = self._handle_lookup_domain(param)

        elif action_id == 'lookup_hash':
            ret_val = self._handle_lookup_hash(param)

        elif action_id == 'lookup_ip':
            ret_val = self._handle_lookup_ip(param)

        elif action_id == 'whois_domain':
            ret_val = self._handle_whois_domain(param)

        elif action_id == 'reverse_ip':
            ret_val = self._handle_reverse_ip(param)

        elif action_id == 'whois_ip':
            ret_val = self._handle_whois_ip(param)

        elif action_id == 'lookup_av':
            ret_val = self._handle_lookup_av(param)

        elif action_id == 'lookup_ssl':
            ret_val = self._handle_lookup_ssl(param)

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

        self._base_url = config.get('base_url').encode('utf-8')
        self.set_validator('ipv6', self._is_ip)

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

        connector = ThreatminerApiConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
