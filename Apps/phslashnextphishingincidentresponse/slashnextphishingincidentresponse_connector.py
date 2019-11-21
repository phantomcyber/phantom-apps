# File: slashnextphishingincidentresponse_connector.py
# Copyright (c) 2019 SlashNext Inc. (www.slashnext.com)
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

"""
Created on August 20, 2019

@author: Saadat Abid, Umair Ahmad
"""

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from slashnextphishingincidentresponse_consts import *
import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class SlashnextPhishingIncidentResponseConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(SlashnextPhishingIncidentResponseConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so, please
        # modify this as you deem fit.
        self._base_url = None
        self._api_key = None

    def _process_empty_response(self, response, action_result):

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

        message = message.replace(u'{', '{{').replace(u'}', '}}')

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
                r.status_code, r.text.replace(u'{', '{{').replace(u'}', '}}'))

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
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

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
                            # auth=(username, password),  # basic authentication
                            verify=config.get('verify_server_cert', False),
                            **kwargs)
        except Exception as e:
            return RetVal(action_result.set_status(
                phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    # def _handle_ip_reputation(self, param):
    #     self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
    #     action_result = self.add_action_result(ActionResult(dict(param)))
    #
    #     ip = param['ip']
    #
    #     # API call parameters
    #     ep_params = {
    #         'authkey': self._api_key,
    #         'host': ip
    #     }
    #
    #     # Get the IP reputation data
    #     ret_val, response = self._make_rest_call('/oti/v1/host/reputation', action_result, method="post",
    #                                              params=ep_params, headers=None)
    #
    #     if phantom.is_fail(ret_val):
    #         # Server did not return status code: 200
    #         msg = 'IP Reputation Failed, Error Reason: Error connecting to SlashNext Cloud'
    #         self.save_progress(msg)
    #         return action_result.set_status(phantom.APP_ERROR, msg)
    #
    #     elif response['errorNo'] == 0:
    #         # Success
    #         msg = 'IP Reputation Passed'
    #         self.save_progress(msg)
    #         action_result.add_data(response)
    #
    #         # Add IP verdict as summary
    #         summary = action_result.update_summary({})
    #         summary['Verdict'] = response['threatData']['verdict']
    #
    #         return action_result.set_status(phantom.APP_SUCCESS, msg)
    #
    #     # If there is an error then return the exact error message
    #     else:
    #         msg = 'IP Reputation Failed, Error Reason: {0}'.format(response['errorMsg'])
    #         self.save_progress(msg)
    #         return action_result.set_status(phantom.APP_ERROR, msg)

    # def _handle_url_reputation(self, param):
    #     self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
    #     action_result = self.add_action_result(ActionResult(dict(param)))
    #
    #     url = param['url']
    #
    #     # API call parameters
    #     ep_params = {
    #         'authkey': self._api_key,
    #         'url': url
    #     }
    #
    #     # Getting the URL Reputation data
    #     ret_val, response = self._make_rest_call('/oti/v1/url/reputation', action_result, method="post",
    #                                              params=ep_params, headers=None)
    #
    #     if phantom.is_fail(ret_val):
    #         # Server did not return status code: 200
    #         msg = 'URL Reputation Failed, Error Reason: Error connecting to SlashNext Cloud'
    #         self.save_progress(msg)
    #         return action_result.set_status(phantom.APP_ERROR, msg)
    #
    #     elif response['errorNo'] == 0:
    #         # Success
    #         msg = 'URL Reputation Passed'
    #         self.save_progress(msg)
    #         action_result.add_data(response)
    #
    #         summary = action_result.update_summary({})
    #         # If Intel exists for the scanned URL
    #         if 'urlData' in response:
    #             # Adding URL Verdict and Scan Id as summary
    #             summary['Verdict'] = response['urlData']['threatData']['verdict']
    #             summary['Scan Id'] = response['urlData']['scanId']
    #         else:
    #             summary['Verdict'] = "Unrated, No Intel Found"
    #
    #         return action_result.set_status(phantom.APP_SUCCESS, msg)
    #
    #     # If there is an error then return the exact error message
    #     else:
    #         msg = 'URL Reputation Failed, Error Reason: {0}'.format(response['errorMsg'])
    #         self.save_progress(msg)
    #         return action_result.set_status(phantom.APP_ERROR, msg)

    def _download_forensics(self, action_result, scanid, success_msg):

        # Keeping track of the failures
        actions_failed = 0
        msg = ''

        # --------------------------- Downloading Screenshot ---------------------------
        # Saving action progress
        self.save_progress('Downloading Screenshot')

        # Populate the API parameter dictionary
        ep_params = {
            'authkey': self._api_key,
            'scanid': scanid,
            'resolution': 'medium'
        }

        # Make rest API call
        ret_val, response = self._make_rest_call(
            DL_SC_API, action_result, method='post', params=ep_params, headers=None)

        # Server did not return status code: 200, return error
        if phantom.is_fail(ret_val):
            self.save_progress('Download Screenshot Failed, Error Reason: Error connecting to SlashNext Cloud')
            actions_failed += 1

        # Return success
        elif response['errorNo'] == 0:
            self.save_progress('Download Screenshot Successful')
            action_result.add_data(response)

        # If there is an error then return the exact error message
        else:
            self.save_progress('Download Screenshot Failed, Error Reason: {0}'.format(response['errorMsg']))
            msg = response['errorMsg']
            actions_failed += 1

        # --------------------------- Downloading HTML ---------------------------
        # Saving action progress
        self.save_progress('Downloading HTML')

        # Populate the API parameter dictionary
        ep_params = {
            'authkey': self._api_key,
            'scanid': scanid
        }

        # Make rest API call
        ret_val, response = self._make_rest_call(
            DL_HTML_API, action_result, method='post', params=ep_params, headers=None)

        # Server did not return status code: 200, return error
        if phantom.is_fail(ret_val):
            self.save_progress('Download HTML Failed, Error Reason: Error connecting to SlashNext Cloud')
            actions_failed += 1

        # Return success
        elif response['errorNo'] == 0:
            self.save_progress('Download HTML Successful')
            action_result.add_data(response)

        # If there is an error then return the exact error message
        else:
            self.save_progress('Download HTML Failed, Error Reason: {0}'.format(response['errorMsg']))
            actions_failed += 1

        # --------------------------- Downloading Text ---------------------------
        # Saving action progress
        self.save_progress('Downloading Text')

        # Populate the API parameter dictionary
        ep_params = {
            'authkey': self._api_key,
            'scanid': scanid
        }

        # Make rest API call
        ret_val, response = self._make_rest_call(
            DL_TEXT_API, action_result, method='post', params=ep_params, headers=None)

        # Server did not return status code: 200, return error
        if phantom.is_fail(ret_val):
            self.save_progress('Download Text Failed, Error Reason: Error connecting to SlashNext Cloud')
            actions_failed += 1

        # Return success
        elif response['errorNo'] == 0:
            self.save_progress('Download Text Successful')
            action_result.add_data(response)

        # If there is an error then return the exact error message
        else:
            self.save_progress('Download Text Failed, Error Reason: {0}'.format(response['errorMsg']))
            actions_failed += 1

        # All the actions failed, so display an notification
        if actions_failed == 3:
            self.save_progress('Failed to download screenshot, HTML and text data')
            return action_result.set_status(phantom.APP_SUCCESS, msg)
        else:
            self.save_progress('Successful either download screenshot, HTML or/and text data ')
            return action_result.set_status(phantom.APP_SUCCESS, success_msg)

    def _handle_test_connectivity(self, param):

        # Saving action progress
        self.save_progress('Connecting to endpoint')

        # Adding input parameters to the action results
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Populate the API parameter dictionary
        ep_params = {
            'authkey': self._api_key,
            'host': 'www.google.com'
        }

        # Making a call to OTI Host Reputation API to test connectivity with OTI Cloud
        ret_val, response = self._make_rest_call(
            HOST_REPUTE_API, action_result, method='post', params=ep_params, headers=None)

        # Server did not return status code: 200, return error
        if phantom.is_fail(ret_val):
            self.save_progress('Test Connectivity Failed')
            msg = 'Error Reason: Error connecting to SlashNext Cloud'
            return action_result.set_status(phantom.APP_ERROR, msg)

        # Return success
        elif response['errorNo'] == 0:
            msg = 'Test Connectivity Successful'
            self.save_progress(msg)
            return action_result.set_status(phantom.APP_SUCCESS)

        # If there is an error then return the exact error message
        else:
            self.save_progress('Test Connectivity Failed')
            msg = 'Error Reason: {0}'.format(response['errorMsg'])
            return action_result.set_status(phantom.APP_ERROR, msg)

    def _handle_api_quota(self, param):

        # Saving action progress
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        # Adding input parameters to the action results
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Return success
        msg = 'Coming Soon...'
        self.save_progress(msg)
        return action_result.set_status(phantom.APP_SUCCESS, msg)

    def _handle_host_reputation(self, param):

        # Saving action progress
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        # Adding input parameters to the action results
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Accessing action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        host = param['host']

        # Populate the API parameter dictionary
        ep_params = {
            'authkey': self._api_key,
            'host': host
        }

        # Make rest API call
        ret_val, response = self._make_rest_call(
            HOST_REPUTE_API, action_result, method='post', params=ep_params, headers=None)

        # Server did not return status code: 200, return error
        if phantom.is_fail(ret_val):
            msg = 'Host Reputation Failed, Error Reason: Error connecting to SlashNext Cloud'
            self.save_progress(msg)
            action_result.update_summary({
                'State': 'Connection Error'
            })
            return action_result.set_status(phantom.APP_ERROR, msg)

        # Return success
        elif response['errorNo'] == 0:
            msg = 'Host Reputation Successful'
            self.save_progress(msg)
            action_result.add_data(response)
            action_result.update_summary({
                'State': 'Reputation Fetched',
                'Verdict': response['threatData']['verdict']
            })
            return action_result.set_status(phantom.APP_SUCCESS, msg)

        # If there is an error then return the exact error message
        else:
            msg = 'Host Reputation Failed, Error Reason: {0}'.format(response['errorMsg'])
            self.save_progress(msg)
            action_result.add_data(response)
            action_result.update_summary({
                'State': 'API Error'
            })
            return action_result.set_status(phantom.APP_ERROR, msg)

    def _handle_host_urls(self, param):

        # Saving action progress
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        # Adding input parameters to the action results
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Accessing action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        host = param['host']

        # Optional values should use the .get() function
        limit = param.get('limit', 10)

        # Populate the API parameter dictionary
        ep_params = {
            'authkey': self._api_key,
            'host': host,
            'page': 1,
            'rpp': limit
        }

        # Make rest API call
        ret_val, response = self._make_rest_call(
            HOST_REPORT_API, action_result, method='post', params=ep_params, headers=None)

        # Server did not return status code: 200, return error
        if phantom.is_fail(ret_val):
            msg = 'Host URLs Failed, Error Reason: Error connecting to SlashNext Cloud'
            self.save_progress(msg)
            action_result.update_summary({
                'State': 'Connection Error'
            })
            return action_result.set_status(phantom.APP_ERROR, msg)

        # Return success
        elif response['errorNo'] == 0:
            msg = 'Host URLs Successful'
            self.save_progress(msg)
            action_result.add_data(response)
            action_result.update_summary({
                'State': 'URLs Fetched',
                'URLs Found': len(response['urlDataList'])
            })
            return action_result.set_status(phantom.APP_SUCCESS, msg)

        # If there is an error then return the exact error message
        else:
            msg = 'Host URLs Failed, Error Reason: {0}'.format(response['errorMsg'])
            self.save_progress(msg)
            action_result.add_data(response)
            action_result.update_summary({
                'State': 'API Error'
            })
            return action_result.set_status(phantom.APP_ERROR, msg)

    def _handle_host_report(self, param):

        # Saving action progress
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        # Adding input parameters to the action results
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Accessing action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        host = param['host']

        # --------------------------- Host Reputation ---------------------------
        # Populate the API parameter dictionary
        ep_params = {
            'authkey': self._api_key,
            'host': host
        }

        # Make rest API call
        ret_val, response = self._make_rest_call(
            HOST_REPUTE_API, action_result, method='post', params=ep_params, headers=None)

        # Server did not return status code: 200, return error
        if phantom.is_fail(ret_val):
            msg = 'Host Reputation Failed, Error Reason: Error connecting to SlashNext Cloud'
            self.save_progress(msg)
            action_result.update_summary({
                'State': 'Connection Error'
            })
            return action_result.set_status(phantom.APP_ERROR, msg)

        # Return success
        elif response['errorNo'] == 0:
            self.save_progress('Host Report Successful')
            action_result.add_data(response)
            action_result.update_summary({
                'State': 'Report Fetched',
                'Verdict': response['threatData']['verdict']
            })

            if response.get('threatData').get('verdict').startswith('Unrated'):
                msg = 'Host Reputation Returned: {0}'.format(response.get('threatData').get('verdict'))
                self.save_progress(msg)
                return action_result.set_status(phantom.APP_SUCCESS, msg)

        # If there is an error then return the exact error message
        else:
            msg = 'Host Reputation Failed, Error Reason: {0}'.format(response['errorMsg'])
            self.save_progress(msg)
            action_result.add_data(response)
            action_result.update_summary({
                'State': 'API Error'
            })
            return action_result.set_status(phantom.APP_ERROR, msg)

        # --------------------------- Host Report ---------------------------
        # Populate the API parameter dictionary
        ep_params = {
            'authkey': self._api_key,
            'host': host,
            'page': 1,
            'rpp': 1
        }

        # Make rest API call
        ret_val, response = self._make_rest_call(
            HOST_REPORT_API, action_result, method='post', params=ep_params, headers=None)

        # Server did not return status code: 200, return error
        if phantom.is_fail(ret_val):
            msg = 'Host URLs Failed, Error Reason: Error connecting to SlashNext Cloud'
            self.save_progress(msg)
            action_result.update_summary({
                'State': 'Connection Error'
            })
            return action_result.set_status(phantom.APP_ERROR, msg)

        # Return success
        elif response['errorNo'] == 0:
            self.save_progress('Host URLs Successful')

            first_url = response['urlDataList'][0]
            latest_url = first_url['url']
            latest_url_scanid = str(first_url['scanId'])

            # Perform a URL scan if there exists no Scan ID for the URL
            if latest_url_scanid == 'N/A':
                # --------------------------- URL Scan Sync ---------------------------
                # Populate the API parameter dictionary
                ep_params = {
                    'authkey': self._api_key,
                    'url': latest_url
                }

                # Make rest API call
                ret_val, response = self._make_rest_call(
                    URL_SCANSYNC_API, action_result, method='post', params=ep_params, headers=None)

                # Server did not return status code: 200, return error
                if phantom.is_fail(ret_val):
                    msg = 'URL Synchronous Scan Failed, Error Reason: Error connecting to SlashNext Cloud'
                    self.save_progress(msg)
                    action_result.update_summary({
                        'State': 'Connection Error'
                    })
                    return action_result.set_status(phantom.APP_ERROR, msg)

                # Return success
                elif response['errorNo'] == 0:
                    self.save_progress('URL Synchronous Scan Successful')
                    action_result.add_data(response)

                    # If there is landing URL available, get its forensics instead
                    if 'landingUrl' in response['urlData']:
                        # Set the Scan ID to landing URL if it exists
                        latest_url_scanid = response['urlData']['landingUrl']['scanId']
                    else:
                        # Otherwise set it to the scanned URL's scan ID
                        latest_url_scanid = response['urlData']['scanId']

                # If there is an error then return the exact error message
                else:
                    msg = 'URL Synchronous Scan Failed, Error Reason: {0}'.format(response['errorMsg'])
                    self.save_progress(msg)
                    action_result.add_data(response)
                    action_result.update_summary({
                        'State': 'API Error'
                    })
                    return action_result.set_status(phantom.APP_ERROR, msg)

            else:
                # If there is landing URL available, get its forensics instead
                if 'landingUrl' in first_url and first_url['landingUrl']['scanId'] != 'N/A':
                    latest_url_scanid = first_url['landingUrl']['scanId']

                # Add the result of the Host Report
                action_result.add_data(response)

        # If there is an error then return the exact error message
        else:
            msg = 'Host URLs Failed, Error Reason: {0}'.format(response['errorMsg'])
            self.save_progress(msg)
            action_result.add_data(response)
            action_result.update_summary({
                'State': 'API Error'
            })
            return action_result.set_status(phantom.APP_ERROR, msg)

        # --------------------------- Forensics Data ---------------------------
        # Calling the function to collectively download screenshot, HTML and text data
        msg = 'Host Report Successful'
        if response.get('swlData') is None:
            self._download_forensics(action_result, latest_url_scanid, msg)
        else:
            return action_result.set_status(phantom.APP_SUCCESS, msg)

    def _handle_url_scan(self, param):

        # Saving action progress
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        # Adding input parameters to the action results
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Accessing action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        url = param['url']

        # Optional values should use the .get() function
        extended_info = param.get('extended_info', False)

        # Populate the API parameter dictionary
        ep_params = {
            'authkey': self._api_key,
            'url': url
        }

        # Make rest API call
        ret_val, response = self._make_rest_call(
            URL_SCAN_API, action_result, method='post', params=ep_params, headers=None)

        # Server did not return status code: 200, return error
        if phantom.is_fail(ret_val):
            msg = 'URL Scan Failed, Error Reason: Error connecting to SlashNext Cloud'
            self.save_progress(msg)
            action_result.update_summary({
                'State': 'Connection Error'
            })
            return action_result.set_status(phantom.APP_ERROR, msg)

        # Return success
        elif response['errorNo'] == 1:
            msg = 'Your URL Scan request is submitted to the cloud and may take up-to 60 seconds to complete.\n' \
                  'Please check back later using "scan report" action with Scan ID = {0} or '\
                  'running the same "url scan" action one more time'.format(response['urlData']['scanId'])
            self.save_progress(msg)
            action_result.add_data(response)
            action_result.update_summary({
                'State': 'Pending, Retry'
            })
            return action_result.set_status(phantom.APP_SUCCESS, msg)

        # Return success
        elif response['errorNo'] == 0:
            msg = 'URL Scan Successful'
            self.save_progress(msg)
            action_result.add_data(response)

            # Check to see if there is a landing URL so that correct verdict is added
            if response['urlData'].get('landingUrl') is None:
                verdict = response['urlData']['threatData']['verdict']
            else:
                verdict = response['urlData']['landingUrl']['threatData']['verdict']

            action_result.update_summary({
                'State': 'Scan Completed',
                'Verdict': verdict
            })

            # Download the detailed forensics data if extended_info parameter is True
            if extended_info and response.get('swlData') is None:
                self.save_progress('Downloading Forensics Data')

                # If there is landing URL available, get its forensics instead
                if 'landingUrl' in response['urlData']:
                    url_scanid = response['urlData']['landingUrl']['scanId']
                else:
                    url_scanid = response['urlData']['scanId']

                self._download_forensics(action_result, url_scanid, msg)

            else:
                return action_result.set_status(phantom.APP_SUCCESS, msg)

        # If there is an error then return the exact error message
        else:
            msg = 'URL Scan Failed, Error Reason: {0}'.format(response['errorMsg'])
            self.save_progress(msg)
            action_result.add_data(response)
            action_result.update_summary({
                'State': 'API Error'
            })
            return action_result.set_status(phantom.APP_ERROR, msg)

    def _handle_url_scan_sync(self, param):

        # Saving action progress
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        self.save_progress('With parameters: {0}'.format(param))

        # Adding input parameters to the action results
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Accessing action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        url = param['url']

        # Optional values should use the .get() function
        extended_info = param.get('extended_info', False)
        timeout = param.get('timeout', 60)

        # Populate the API parameter dictionary
        ep_params = {
            'authkey': self._api_key,
            'url': url,
            'timeout': timeout
        }

        # Make rest API call
        ret_val, response = self._make_rest_call(
            URL_SCANSYNC_API, action_result, method='post', params=ep_params, headers=None)

        # Server did not return status code: 200, return error
        if phantom.is_fail(ret_val):
            msg = 'URL Synchronous Scan Failed, Error Reason: Error connecting to SlashNext Cloud'
            self.save_progress(msg)
            action_result.update_summary({
                'State': 'Connection Error'
            })
            return action_result.set_status(phantom.APP_ERROR, msg)

        # Return success
        elif response['errorNo'] == 1:
            msg = 'Your URL Scan request is submitted to the cloud and is taking longer than expected to complete.\n' \
                  'Please check back later using scan report action with Scan ID = {0} or ' \
                  'running the same "url scan sync" action one more time'.format(response['urlData']['scanId'])
            self.save_progress(msg)
            action_result.add_data(response)
            action_result.update_summary({
                'State': 'Pending, Retry'
            })
            return action_result.set_status(phantom.APP_SUCCESS, msg)

        # Return success
        elif response['errorNo'] == 0:
            msg = 'URL Scan Successful'
            self.save_progress(msg)
            action_result.add_data(response)

            # Check to see if there is a landing URL so that correct verdict is added
            if response['urlData'].get('landingUrl') is None:
                verdict = response['urlData']['threatData']['verdict']
            else:
                verdict = response['urlData']['landingUrl']['threatData']['verdict']

            action_result.update_summary({
                'State': 'Scan Completed',
                'Verdict': verdict
            })

            # Download the detailed forensics data if extended_info parameter is True
            if extended_info and response.get('swlData') is None:
                self.save_progress('Downloading Forensics Data')

                # If there is landing URL available, get its forensics instead
                if 'landingUrl' in response['urlData']:
                    url_scanid = response['urlData']['landingUrl']['scanId']
                else:
                    url_scanid = response['urlData']['scanId']

                self._download_forensics(action_result, url_scanid, msg)

            else:
                return action_result.set_status(phantom.APP_SUCCESS, msg)

        # If there is an error then return the exact error message
        else:
            msg = 'URL Synchronous Scan Failed, Error Reason: {0}'.format(response['errorMsg'])
            self.save_progress(msg)
            action_result.add_data(response)
            action_result.update_summary({
                'State': 'API Error'
            })
            return action_result.set_status(phantom.APP_ERROR, msg)

    def _handle_scan_report(self, param):

        # Saving action progress
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        # Adding input parameters to the action results
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Accessing action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        scanid = param['scanid']

        # Optional values should use the .get() function
        extended_info = param.get('extended_info', False)

        # Populate the API parameter dictionary
        ep_params = {
            'authkey': self._api_key,
            'scanid': scanid
        }

        # Make rest API call
        ret_val, response = self._make_rest_call(
            URL_SCAN_API, action_result, method='post', params=ep_params, headers=None)

        # Server did not return status code: 200, return error
        if phantom.is_fail(ret_val):
            msg = 'Scan Report Failed, Error Reason: Error connecting to SlashNext Cloud'
            self.save_progress(msg)
            action_result.update_summary({
                'State': 'Connection Error'
            })
            return action_result.set_status(phantom.APP_ERROR, msg)

        # Return success
        elif response['errorNo'] == 1:
            msg = 'Your URL Scan request is submitted to the cloud and may take up-to 60 seconds to complete.\n' \
                  'Please check back later using "scan report" action with Scan ID = {0}'.format(scanid)
            self.save_progress(msg)
            action_result.add_data(response)
            action_result.update_summary({
                'State': 'Pending, Retry'
            })
            return action_result.set_status(phantom.APP_SUCCESS, msg)

        # Return success
        elif response['errorNo'] == 0:
            msg = 'Scan Report Successful'
            self.save_progress(msg)
            action_result.add_data(response)

            # Check to see if there is a landing URL so that correct verdict is added
            if response['urlData'].get('landingUrl') is None:
                verdict = response['urlData']['threatData']['verdict']
            else:
                verdict = response['urlData']['landingUrl']['threatData']['verdict']

            action_result.update_summary({
                'State': 'Scan Completed',
                'Verdict': verdict
            })

            # Download the detailed forensics data if extended_info parameter is True
            if extended_info and response.get('swlData') is None:
                self.save_progress('Downloading Forensics Data')

                # If there is landing URL available, get its forensics instead
                if 'landingUrl' in response['urlData']:
                    url_scanid = response['urlData']['landingUrl']['scanId']
                else:
                    url_scanid = response['urlData']['scanId']

                self._download_forensics(action_result, url_scanid, msg)

            else:
                return action_result.set_status(phantom.APP_SUCCESS, msg)

        # If there is an error then return the exact error message
        else:
            msg = 'Scan Report Failed, Error Reason: {0}'.format(response['errorMsg'])
            self.save_progress(msg)
            action_result.add_data(response)
            action_result.update_summary({
                'State': 'API Error'
            })
            return action_result.set_status(phantom.APP_ERROR, msg)

    def _handle_download_screenshot(self, param):

        # Saving action progress
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        # Adding input parameters to the action results
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Accessing action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        scanid = param['scanid']

        # Populate the API parameter dictionary
        ep_params = {
            'authkey': self._api_key,
            'scanid': scanid,
            'resolution': 'high'
        }

        # Make rest API call
        ret_val, response = self._make_rest_call(
            DL_SC_API, action_result, method='post', params=ep_params, headers=None)

        # Server did not return status code: 200, return error
        if phantom.is_fail(ret_val):
            msg = 'Download Screenshot Failed, Error Reason: Error connecting to SlashNext Cloud'
            self.save_progress(msg)
            action_result.update_summary({
                'State': 'Connection Error'
            })
            return action_result.set_status(phantom.APP_ERROR, msg)

        # Return success
        elif response['errorNo'] == 1:
            msg = 'Your URL Scan request is submitted to the cloud and may take up-to 60 seconds to complete.\n'\
                  'Please check back later using "download screenshot" action with Scan ID = {0}'.format(scanid)
            self.save_progress(msg)
            action_result.add_data(response)
            action_result.update_summary({
                'State': 'Pending, Retry'
            })
            return action_result.set_status(phantom.APP_SUCCESS, msg)

        # Return success
        elif response['errorNo'] == 0:
            msg = 'Download Screenshot Successful'
            self.save_progress(msg)
            action_result.add_data(response)
            action_result.update_summary({
                'State': response['scData']['scName'] + '.jpeg Downloaded'
            })
            return action_result.set_status(phantom.APP_SUCCESS, msg)

        # If there is an error then return the exact error message
        else:
            msg = 'Download Screenshot Failed, Error Reason: {0}'.format(response['errorMsg'])
            self.save_progress(msg)
            action_result.add_data(response)
            action_result.update_summary({
                'State': 'API Error'
            })
            return action_result.set_status(phantom.APP_ERROR, msg)

    def _handle_download_html(self, param):

        # Saving action progress
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        # Adding input parameters to the action results
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Accessing action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        scanid = param['scanid']

        # Populate the API parameter dictionary
        ep_params = {
            'authkey': self._api_key,
            'scanid': scanid
        }

        # Make rest API call
        ret_val, response = self._make_rest_call(
            DL_HTML_API, action_result, method='post', params=ep_params, headers=None)

        # Server did not return status code: 200, return error
        if phantom.is_fail(ret_val):
            msg = 'Download HTML Failed, Error Reason: Error connecting to SlashNext Cloud'
            self.save_progress(msg)
            action_result.update_summary({
                'State': 'Connection Error'
            })
            return action_result.set_status(phantom.APP_ERROR, msg)

        # Return success
        elif response['errorNo'] == 1:
            msg = 'Your URL Scan request is submitted to the cloud and may take up-to 60 seconds to complete.\n'\
                  'Please check back later using "download html" action with Scan ID = {0}'.format(scanid)
            self.save_progress(msg)
            action_result.add_data(response)
            action_result.update_summary({
                'State': 'Pending, Retry'
            })
            return action_result.set_status(phantom.APP_SUCCESS, msg)

        # Return success
        elif response['errorNo'] == 0:
            msg = 'Download HTML Successful'
            self.save_progress(msg)
            action_result.add_data(response)
            action_result.update_summary({
                'State': response['htmlData']['htmlName'] + '.html Downloaded'
            })
            return action_result.set_status(phantom.APP_SUCCESS, msg)

        # If there is an error then return the exact error message
        else:
            msg = 'Download HTML Failed, Error Reason: {0}'.format(response['errorMsg'])
            self.save_progress(msg)
            action_result.add_data(response)
            action_result.update_summary({
                'State': 'API Error'
            })
            return action_result.set_status(phantom.APP_ERROR, msg)

    def _handle_download_text(self, param):

        # Saving action progress
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        # Adding input parameters to the action results
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Accessing action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        scanid = param['scanid']

        # Populate the API parameter dictionary
        ep_params = {
            'authkey': self._api_key,
            'scanid': scanid
        }

        # Make rest API call
        ret_val, response = self._make_rest_call(
            DL_TEXT_API, action_result, method='post', params=ep_params, headers=None)

        # Server did not return status code: 200, return error
        if phantom.is_fail(ret_val):
            msg = 'Download Text Failed, Error Reason: Error connecting to SlashNext Cloud'
            self.save_progress(msg)
            action_result.update_summary({
                'State': 'Connection Error'
            })
            return action_result.set_status(phantom.APP_ERROR, msg)

        # Return success
        elif response['errorNo'] == 1:
            msg = 'Your URL Scan request is submitted to the cloud and may take up-to 60 seconds to complete.\n'\
                  'Please check back later using "download text" action with Scan ID = {0}'.format(scanid)
            self.save_progress(msg)
            action_result.add_data(response)
            action_result.update_summary({
                'State': 'Pending, Retry'
            })
            return action_result.set_status(phantom.APP_SUCCESS, msg)

        # Return success
        elif response['errorNo'] == 0:
            msg = 'Download Text Successful'
            self.save_progress(msg)
            action_result.add_data(response)
            action_result.update_summary({
                'State': response['textData']['textName'] + '.txt Downloaded'
            })
            return action_result.set_status(phantom.APP_SUCCESS, msg)

        # If there is an error then return the exact error message
        else:
            msg = 'Download Text Failed, Error Reason: {0}'.format(response['errorMsg'])
            self.save_progress(msg)
            action_result.add_data(response)
            action_result.update_summary({
                'State': 'API Error'
            })
            return action_result.set_status(phantom.APP_ERROR, msg)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'api_quota':
            ret_val = self._handle_api_quota(param)

        elif action_id == 'host_reputation':
            ret_val = self._handle_host_reputation(param)

        elif action_id == 'host_urls':
            ret_val = self._handle_host_urls(param)

        elif action_id == 'host_report':
            ret_val = self._handle_host_report(param)

        elif action_id == 'url_scan':
            ret_val = self._handle_url_scan(param)

        elif action_id == 'url_scan_sync':
            ret_val = self._handle_url_scan_sync(param)

        elif action_id == 'scan_report':
            ret_val = self._handle_scan_report(param)

        elif action_id == 'download_screenshot':
            ret_val = self._handle_download_screenshot(param)

        elif action_id == 'download_html':
            ret_val = self._handle_download_html(param)

        elif action_id == 'download_text':
            ret_val = self._handle_download_text(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # Get the asset config
        config = self.get_config()

        # Access values in asset config by the name
        # Required values can be accessed directly
        self._api_key = config['api_key']

        # Optional values should use the .get() function
        self._base_url = config.get('api_base_url', BASE_API)

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
            login_url = SlashnextPhishingIncidentResponseConnector._get_phantom_base_url() + '/login'

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

        connector = SlashnextPhishingIncidentResponseConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
