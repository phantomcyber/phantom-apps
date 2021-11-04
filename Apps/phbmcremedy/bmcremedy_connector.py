# File: bmcremedy_connector.py
# Copyright (c) 2017-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Standard library imports
import json
import re
import requests
from bs4 import BeautifulSoup

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import phantom.rules as ph_rules

# Local imports
import bmcremedy_consts as consts


class RetVal3(tuple):
    def __new__(cls, val1, val2=None, val3=None):
        return tuple.__new__(RetVal3, (val1, val2, val3))


class BmcremedyConnector(BaseConnector):
    """ This is an AppConnector class that inherits the BaseConnector class. It implements various actions supported by
    BMC Remedy and helper methods required to run the actions.
    """

    def __init__(self):

        # Calling the BaseConnector's init function
        super(BmcremedyConnector, self).__init__()
        self._base_url = None
        self._api_username = None
        self._api_password = None
        self._token = None
        self._verify_server_cert = None
        self._state = dict()
        return

    def initialize(self):
        """ This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """

        config = self.get_config()

        # Initialize configuration parameters
        self._base_url = config[consts.BMCREMEDY_CONFIG_SERVER].strip('/')
        self._api_username = config[consts.BMCREMEDY_CONFIG_API_USERNAME]
        self._api_password = config[consts.BMCREMEDY_CONFIG_API_PASSWORD]
        self._verify_server_cert = config.get(consts.BMCREMEDY_CONFIG_SERVER_CERT, False)

        # Load any saved configurations
        self._state = self.load_state()
        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {
                "app_version": self.get_app_json().get('app_version')
            }
            return self.set_status(phantom.APP_ERROR, consts.BMCREMEDY_STATE_FILE_CORRUPT_ERR)

        self._token = self._state.get('token')

        # Return response_status
        return phantom.APP_SUCCESS

    def _check_login_status(self, action_result, response):

        if not hasattr(response, 'headers'):
            return action_result.set_status(phantom.APP_ERROR, "Response missing headers, cannot determine success")

        x_ar_messages = response.headers.get('x-ar-messages')
        if not x_ar_messages:
            return phantom.APP_SUCCESS

        # will need to parse the messages
        try:
            x_ar_messages = json.loads(x_ar_messages)
        except:
            return action_result.set_status(phantom.APP_ERROR, "Unable to process X-AR-Messages")

        for curr_msg_dict in x_ar_messages:
            message_text = curr_msg_dict.get('messageText')
            if not message_text:
                continue
            if 'login failed' in message_text.lower():
                return action_result.set_status(phantom.APP_ERROR, "Login failed, please check your credentials")

        return phantom.APP_SUCCESS

    def _get_error_message_from_exception(self, e):
        """
        Get appropriate error message from the exception.

        :param e: Exception object
        :return: error message
        """
        error_code = consts.ERR_CODE_MSG
        error_msg = consts.ERR_MSG_UNAVAILABLE

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = consts.ERR_CODE_MSG
                    error_msg = e.args[0]
        except:
            pass

        try:
            if error_code in consts.ERR_CODE_MSG:
                error_text = "Error Message: {}".format(error_msg)
            else:
                error_text = "Error Code: {}. Error Message: {}".format(error_code, error_msg)
        except:
            self.debug_print(consts.PARSE_ERR_MSG)
            error_text = consts.PARSE_ERR_MSG

        return error_text

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        """
        Validate an integer.

        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :param key: input parameter message key
        :allow_zero: whether zero should be considered as valid value or not
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, integer value of the parameter or None in case of failure
        """
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_VALID_INT_MSG.format(param=key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_VALID_INT_MSG.format(param=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_NON_NEG_INT_MSG.format(param=key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_NON_NEG_NON_ZERO_INT_MSG.format(param=key)), None

        return phantom.APP_SUCCESS, parameter

    def _parse_html_response(self, response):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
               element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        if not error_text:
            error_text = "Empty response and no information received"
        message = "Status Code: {}. Error Details: {}".format(status_code, error_text)
        message = message.replace('{', '{{').replace('}', '}}')
        return message

    def _generate_api_token(self, action_result):
        """ Generate new token based on the credentials provided. Token generated is valid for 60 minutes.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        self._token = ""

        # Prepare request headers
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        # Prepare request body
        payload = {'username': self._api_username, 'password': self._api_password}

        # Make call
        response_status, response_dict, response = self._make_rest_call(consts.BMCREMEDY_TOKEN_ENDPOINT, action_result,
                                                              headers=headers, data=payload)

        # Something went wrong with the request
        if phantom.is_fail(response_status):
            return action_result.get_status()

        if not response_dict:
            self.debug_print(consts.BMCREMEDY_TOKEN_GENERATION_ERROR_MSG)
            return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_TOKEN_GENERATION_ERROR_MSG)

        # check the header for any message that denote a failure
        ret_val = self._check_login_status(action_result, response)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Saving the token to be used in subsequent actions
        self._state['token'] = self._token = response_dict["content"].decode("utf-8")

        return phantom.APP_SUCCESS

    def _provide_attachment_details(self, attachment_list, action_result):
        """ Helper function that is used to get attachment from the vault, and provide attachment details which can be
        used to add attachment to an incident.

        :param attachment_list: list of vault IDs
        :param action_result: object of ActionResult class
        :return: status (success/failure) and (add_attachment_params_dict dictionary having attachment related
                            information and attachment_data dictionary containing attachment) / None
        """

        file_obj = []
        filename = []
        attachment_data = dict()
        add_attachment_params_dict = dict()

        attachment_list = [value.strip() for value in attachment_list.split(',') if value.strip()]
        if not attachment_list:
            self.debug_print(consts.BMCREMEDY_ERR_INVALID_FIELDS.format(field='vault_id'))
            return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_ERR_INVALID_FIELDS.format(field='vault_id')), None, None

        # At most, three attachments should be provided
        if len(attachment_list) > 3:
            self.debug_print(consts.BMCREMEDY_ATTACHMENT_LIMIT_EXCEED)
            return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_ATTACHMENT_LIMIT_EXCEED), None, None

        try:
            # Searching for file with vault id in current container
            _, _, files_array = (ph_rules.vault_info(container_id=self.get_container_id()))
            files_array = list(files_array)
            for vault_id in attachment_list:
                file_found = False
                for file_data in files_array:
                    if file_data[consts.BMCREMEDY_JSON_VAULT_ID] == vault_id:
                        # Getting filename to use
                        filename.append(file_data['name'])
                        # Reading binary data of file
                        with open(file_data.get('path'), 'rb') as f:
                            file_obj.append(f.read())
                        file_found = True
                        break
                if not file_found:
                    self.debug_print("{}: {}".format(consts.BMCREMEDY_UNKNOWN_VAULT_ID, vault_id))
                    return action_result.set_status(phantom.APP_ERROR, "{}: {}".format(consts.BMCREMEDY_UNKNOWN_VAULT_ID, vault_id)), None, None
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, err_msg), None, None

        for index, value in enumerate(file_obj):
            add_attachment_params_dict['z2AF Work Log0{}'.format(index + 1)] = filename[index]
            attachment_data['attach-z2AF Work Log0{}'.format(index + 1)] = (filename[index], value)

        return phantom.APP_SUCCESS, add_attachment_params_dict, attachment_data

    def _add_attachment(self, attachment_data, action_result):
        """ Helper function used to add attachment to an incident.

        :param attachment_data: dictionary containing details of attachment
        :param action_result: Object of ActionResult() class
        :return: status (success/failure) and (response obtained after adding attachment or None)
        """

        # If attachment is to be added, then details will be provided in 'entry' field
        files = []
        data_params = None
        if "entry" in attachment_data:
            for key, value in attachment_data.items():
                if key == "entry":
                    tup = (key, (None, json.dumps(value).encode(), 'text/json'))
                else:
                    tup = (key, (value[0], value[1]))
                files.append(tup)
        else:
            data_params = json.dumps(attachment_data)

        # Create incident using given input parameters
        response_status, response_data = self._make_rest_call_abstract(consts.BMCREMEDY_COMMENT_ENDPOINT, action_result,
                                                                       data=data_params, method="post",
                                                                       files=files)
        if phantom.is_fail(response_status):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, response_data

    def _get_url(self, action_result, incident_number):
        """ Helper function returns the url for the set status and update ticket action.

        :param incident_number: ID of incident
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message) and url to be used
        """

        params = {'q': "'Incident Number'=\"{}\"".format(incident_number)}

        response_status, response_data = self._make_rest_call_abstract(consts.BMCREMEDY_GET_TICKET, action_result,
                                                                       params=params, method='get')

        if phantom.is_fail(response_status):
            return phantom.APP_ERROR, None

        # If incident is not found
        if not response_data.get("entries"):
            return phantom.APP_SUCCESS, None

        try:
            url = response_data["entries"][0].get('_links', {}).get('self', [])[0].get('href', None)
            if url:
                url = re.findall("(?:/api).*", url)[0]

        except Exception as e:
            self.debug_print(consts.BMCREMEDY_ERROR_FETCHING_URL.format(error=e))
            return phantom.APP_ERROR, None

        return phantom.APP_SUCCESS, url

    def _make_rest_call_abstract(self, endpoint, action_result, data=None, params=None, method="post",
                                 accept_headers=None, files=None):
        """ This method generates a new token if it is not available or if the existing token has expired
        and makes the call using _make_rest_call method.

        :param endpoint: REST endpoint
        :param action_result: object of ActionResult class
        :param data: request body
        :param params: request params
        :param method: GET/POST/PUT/DELETE (Default will be POST)
        :param accept_headers: requests headers
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message) and API response
        """

        # Use this object for _make_rest_call
        # Final status of action_result will be determined after retry, in case the token is expired
        intermediate_action_result = ActionResult()
        response_data = None

        # Generate new token if not available
        if not self._token:
            ret_code = self._generate_api_token(action_result)
            if phantom.is_fail(ret_code):
                return action_result.get_status(), response_data

        # Prepare request headers
        if files:
            headers = {"Authorization": f"AR-JWT {self._token}"}
        else:
            headers = {'Content-Type': 'application/json', "Authorization": f"AR-JWT {self._token}"}

        # Updating headers if Content-Type is 'multipart/formdata'
        if accept_headers:
            headers.update(accept_headers)

        # Make call
        rest_ret_code, response_data, response = self._make_rest_call(endpoint, intermediate_action_result, headers=headers,
                                                       params=params, data=data, method=method, files=files)

        # If token is invalid in case of API call, generate new token and retry
        if str(consts.BMCREMEDY_REST_RESP_UNAUTHORIZED) in str(intermediate_action_result.get_message()):
            ret_code = self._generate_api_token(action_result)
            if phantom.is_fail(ret_code):
                return action_result.get_status(), response_data

            # Update headers with new token
            headers["Authorization"] = "AR-JWT {}".format(self._token)
            # Retry the REST call with new token generated
            rest_ret_code, response_data, response = self._make_rest_call(endpoint, intermediate_action_result, headers=headers,
                                                           params=params, data=data, method=method)

        # Assigning intermediate action_result to action_result, since no further invocation required
        if phantom.is_fail(rest_ret_code):
            action_result.set_status(rest_ret_code, intermediate_action_result.get_message())
            return action_result.get_status(), response_data

        return phantom.APP_SUCCESS, response_data

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="post", files=None):
        """ Function that makes the REST call to the device. It's a generic function that can be called from various
        action handlers.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param method: GET/POST/PUT/DELETE (Default will be POST)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        response_data = None
        response = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            self.debug_print(consts.BMCREMEDY_ERR_API_UNSUPPORTED_METHOD.format(method=method))
            # Set the action_result status to error, the handler function will most probably return as is
            return RetVal3(action_result.set_status(phantom.APP_ERROR), response_data, response)
        except Exception as e:
            error_msg = "{}. {}".format(consts.BMCREMEDY_EXCEPTION_OCCURRED, self._get_error_message_from_exception(e))
            self.debug_print(error_msg)
            # Set the action_result status to error, the handler function will most probably return as is
            return RetVal3(action_result.set_status(phantom.APP_ERROR, error_msg), response_data, response)

        try:
            if files:
                response = request_func('{}{}'.format(self._base_url, endpoint), headers=headers, files=files,
                                    verify=self._verify_server_cert)
            else:
                response = request_func('{}{}'.format(self._base_url, endpoint), headers=headers, data=data, params=params,
                                        verify=self._verify_server_cert)
        except requests.exceptions.ConnectionError as e:
            self.debug_print(self._get_error_message_from_exception(e))
            error_msg = "Error connecting to server. Connection refused from server for {}".format('{}{}'.format(self._base_url, endpoint))
            return RetVal3(action_result.set_status(phantom.APP_ERROR, error_msg), response_data, response)
        except Exception as error:
            error_msg = self._get_error_message_from_exception(error)
            self.debug_print(consts.BMCREMEDY_REST_CALL_ERROR.format(error=error_msg))
            # Set the action_result status to error, the handler function will most probably return as is
            action_result_error_msg = "{}. {}".format(consts.BMCREMEDY_ERR_SERVER_CONNECTION, error_msg)
            return RetVal3(action_result.set_status(phantom.APP_ERROR, action_result_error_msg), response_data, response)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in response.headers.get('content-type', ''):
            response_message = self._parse_html_response(response)
            return RetVal3(action_result.set_status(phantom.APP_ERROR, response_message), response_data, response)

        if response.status_code in consts.ERROR_RESPONSE_DICT:
            self.debug_print(consts.BMCREMEDY_ERR_FROM_SERVER.format(status=response.status_code,
                                                                     detail=consts.ERROR_RESPONSE_DICT[response.status_code]))

            response_data = {"content": response.content, "headers": response.headers}

            response_message = ""
            custom_error_message = ""
            if response_data and response_data.get('content'):
                try:
                    content_dict = json.loads(response_data.get("content"))[0]
                    if consts.BMCREMEDY_BLANK_PARAM_ERROR_SUBSTRING in content_dict.get('messageAppendedText'):
                        custom_error_message = consts.BMCREMEDY_CUSTOM_ERROR_MSG

                    message_text = content_dict.get('messageText')
                    message_appended_text = content_dict.get('messageAppendedText')
                    if custom_error_message:
                        message_appended_text = "{}{}".format(custom_error_message, message_appended_text)
                    response_message = 'Message Text: {}. Message Appended Text: {}'.format(
                        message_text, message_appended_text
                    )
                except:
                    response_message = consts.BMCREMEDY_ERR_JSON_PARSE.format(raw_text=response.text)
                    self.debug_print(response_message)

            # Set the action_result status to error, the handler function will most probably return as is
            action_result_error_msg = "{}. {}".format(
                consts.BMCREMEDY_ERR_FROM_SERVER.format(status=response.status_code, detail=consts.ERROR_RESPONSE_DICT[response.status_code]),
                response_message
            )
            return RetVal3(action_result.set_status(phantom.APP_ERROR, action_result_error_msg), response_data, response)

        # Try parsing response, even in the case of an HTTP error the data might contain a json of details 'message'
        try:
            content_type = response.headers.get('content-type')
            if content_type and content_type.find('json') != -1:
                response_data = response.json()
            else:
                response_data = {"content": response.content, "headers": response.headers}
        except:
            # response.text is guaranteed to be NON None, it will be empty, but not None
            msg_string = consts.BMCREMEDY_ERR_JSON_PARSE.format(raw_text=response.text)
            self.debug_print(msg_string)
            # Set the action_result status to error, the handler function will most probably return as is
            return RetVal3(action_result.set_status(phantom.APP_ERROR, msg_string), response_data, response)

        if response.status_code in consts.SUCCESS_RESPONSE_CODES:
            return RetVal3(action_result.set_status(phantom.APP_SUCCESS), response_data, response)

        # See if an error message is present
        message = response_data.get('message', consts.BMCREMEDY_REST_RESP_OTHER_ERROR_MSG)
        error_message = consts.BMCREMEDY_ERR_FROM_SERVER.format(status=response.status_code, detail=message)
        self.debug_print(error_message)

        # Set the action_result status to error, the handler function will most probably return as is
        return RetVal3(action_result.set_status(phantom.APP_ERROR, error_message), response_data, response)

    def _test_asset_connectivity(self, param):
        """ This function tests the connectivity of an asset with given credentials.

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress(consts.BMCREMEDY_TEST_CONNECTIVITY_MSG)
        self.save_progress("Configured URL: {}".format(self._base_url))

        response_status = self._generate_api_token(action_result)

        if phantom.is_fail(response_status):
            self.save_progress(consts.BMCREMEDY_TEST_CONNECTIVITY_FAIL)
            return action_result.get_status()

        self.save_progress(consts.BMCREMEDY_TEST_CONNECTIVITY_PASS)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _create_ticket(self, param):
        """ This function is used to create an incident.

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        attachment_data = dict()
        add_attachment_details_param = dict()

        # List of recommended parameters that will be checked if user provided in corresponding input parameter
        incident_details_params = ["First_Name", "Last_Name", "Description", "Reported Source", "Service_Type",
                                   "Status", "Urgency", "Impact", "Status_Reason"]

        # Get optional parameters
        work_log_type = param.get(consts.BMCREMEDY_COMMENT_ACTIVITY_TYPE)
        fields_param = param.get(consts.BMCREMEDY_JSON_FIELDS, '{}')

        try:
            fields_param = json.loads(fields_param)
            if isinstance(fields_param, list):
                return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_FIELDS_PARAM_ERR_MSG)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.debug_print(consts.BMCREMEDY_JSON_LOADS_ERROR.format(error_msg))
            return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_JSON_LOADS_ERROR.format(error_msg))

        attachment_list = param.get(consts.BMCREMEDY_JSON_VAULT_ID, '')

        if attachment_list:
            # Segregating attachment related fields from 'fields_param', and creating a dictionary that will contain
            # attachment related information
            vault_details_status, add_attachment_details_param, attachment_data = \
                self._provide_attachment_details(attachment_list, action_result)

            # Something went wrong while executing request
            if phantom.is_fail(vault_details_status):
                return action_result.get_status()

        if work_log_type:
            add_attachment_details_param["Work Log Type"] = work_log_type

        # Getting parameters that are related to adding attachment
        # fields_param may contain extra information apart from details of adding attachment. So getting information
        # about attachments and storing it in a separate dictionary, and removing corresponding details from
        # fields_param, so that fields_param can be used for creating incident.
        for add_attachment_param in consts.ADD_ATTACHMENT_PARAMS_LIST:
            if add_attachment_param in fields_param:
                add_attachment_details_param[add_attachment_param] = fields_param[add_attachment_param]
                fields_param.pop(add_attachment_param)

        # Adding all parameters in 'fields' parameter from corresponding optional parameters, only if not available
        # in 'fields'.
        for create_ticket_param in incident_details_params:
            config_param = create_ticket_param.replace(" ", "_").lower()
            if create_ticket_param not in fields_param and param.get(config_param):
                fields_param[str(create_ticket_param)] = str(param.get(config_param))

        data = json.dumps({"values": fields_param})

        # Create incident using given input parameters
        response_status, response_data = self._make_rest_call_abstract(consts.BMCREMEDY_CREATE_TICKET, action_result,
                                                                       data=data, method="post")

        # Something went wrong while executing request
        if phantom.is_fail(response_status):
            return action_result.get_status()

        if not response_data.get("headers", {}).get("Location"):
            return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_LOCATION_NOT_FOUND)

        # Fetch url to get details of newly created incident
        get_incident_data = re.findall("(?:/api).*", response_data.get("headers", {}).get("Location"))[0]

        # Get details of newly created incident
        response_status, incident_response_data = self._make_rest_call_abstract(get_incident_data, action_result,
                                                                                method="get")

        if phantom.is_fail(response_status):
            return action_result.get_status()

        try:
            if not incident_response_data.get("values", {}).get("Incident Number"):
                return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_INCIDENT_NUMBER_NOT_FOUND)

            summary_data["incident_id"] = incident_response_data.get("values", {})["Incident Number"]

        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.debug_print("Error while summarizing data: {}".format(error_msg))
            return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_SUMMARY_ERROR.format(
                action_name="create_ticket"))

        add_attachment_details_param["Incident Number"] = incident_response_data["values"]["Incident Number"]

        # Adding attachment to newly created incident
        if attachment_list:
            attachment_data["entry"] = {"values": add_attachment_details_param}
        else:
            attachment_data["values"] = add_attachment_details_param

        # Invoking attachment API if relevant fields are present
        if len(add_attachment_details_param.keys()) > 1:
            add_attachment_status, add_attachment_response_data = self._add_attachment(attachment_data, action_result)

            if phantom.is_fail(add_attachment_status):
                return action_result.get_status()

        action_result.add_data(incident_response_data)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _update_ticket(self, param):
        """ This function is used to update an existing incident.

        :param param: includes ID of incident to update
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        attachment_data = dict()
        add_attachment_details_param = dict()

        # Getting optional parameters
        work_log_type = param.get(consts.BMCREMEDY_COMMENT_ACTIVITY_TYPE)

        try:
            fields_param = json.loads(param.get(consts.BMCREMEDY_JSON_FIELDS, '{}'))
            if isinstance(fields_param, list):
                return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_FIELDS_PARAM_ERR_MSG)
        except Exception as e:
            self.debug_print(consts.BMCREMEDY_JSON_LOADS_ERROR.format(e))
            return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_JSON_LOADS_ERROR.format(e))

        incident_number = fields_param.get("Incident Number", param[consts.BMCREMEDY_INCIDENT_NUMBER])

        attachment_list = param.get(consts.BMCREMEDY_JSON_VAULT_ID, '')

        if attachment_list:
            # Segregating attachment related fields from 'fields_param', and creating a dictionary that will contain
            # attachment related information
            vault_details_status, add_attachment_details_param, attachment_data = \
                self._provide_attachment_details(attachment_list, action_result)

            # Something went wrong while executing request
            if phantom.is_fail(vault_details_status):
                return action_result.get_status()

        if work_log_type:
            add_attachment_details_param["Work Log Type"] = work_log_type

        # Getting update link for incident
        return_status, update_link = self._get_url(action_result, incident_number)

        if phantom.is_fail(return_status):
            self.debug_print(consts.BMCREMEDY_URL_NOT_FOUND)
            return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_URL_NOT_FOUND)

        if not update_link:
            return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_INCIDENT_NUMBER_NOT_FOUND)

        # Getting parameters that are related to adding attachment
        # fields_param may contain extra information apart from details of adding attachment. So getting information
        # about attachments and removing corresponding details from fields_param
        for add_attachment_param in consts.ADD_ATTACHMENT_PARAMS_LIST:
            if add_attachment_param in fields_param:
                add_attachment_details_param[add_attachment_param] = fields_param[add_attachment_param]
                fields_param.pop(add_attachment_param)

        if fields_param:
            data = json.dumps({"values": fields_param})

            # Updating incident based on field parameters given by user
            response_status, response_data = self._make_rest_call_abstract(update_link, action_result, data=data,
                                                                           method="put")

            if phantom.is_fail(response_status):
                return action_result.get_status()

        add_attachment_details_param["Incident Number"] = incident_number

        # Adding attachment to the incident
        if attachment_list:
            attachment_data["entry"] = {"values": add_attachment_details_param}
        else:
            attachment_data["values"] = add_attachment_details_param

        # Invoking attachment API if relevant fields are present
        if len(add_attachment_details_param.keys()) > 1:
            add_attachment_status, add_attachment_response_data = self._add_attachment(attachment_data, action_result)

            if phantom.is_fail(add_attachment_status):
                return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, consts.BMCREMEDY_UPDATE_SUCCESSFUL_MSG)

    def _get_ticket(self, param):
        """ Get information for the incident ID provided.

        :param param: includes ID of incident
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Getting mandatory parameter
        incident_id = param[consts.BMCREMEDY_INCIDENT_NUMBER]

        action_params = {'q': "'Incident Number'=\"{}\"".format(incident_id)}

        response_status, ticket_details = self._make_rest_call_abstract(consts.BMCREMEDY_GET_TICKET, action_result,
                                                                        params=action_params, method='get')

        # Something went wrong while executing request
        if phantom.is_fail(response_status):
            return action_result.get_status()

        response_status, ticket_comment_details = self._make_rest_call_abstract(consts.BMCREMEDY_COMMENT_ENDPOINT,
                                                                                action_result, params=action_params,
                                                                                method='get')

        if phantom.is_fail(response_status):
            self.debug_print(consts.BMCREMEDY_GET_COMMENT_ERROR.format(id=incident_id))
            return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_GET_COMMENT_ERROR.format(
                id=incident_id))

        # Adding comments of incident in ticket_details
        ticket_details.update({"work_details": ticket_comment_details})
        action_result.add_data(ticket_details)
        summary_data['ticket_availability'] = True if ticket_details.get('entries') else False

        return action_result.set_status(phantom.APP_SUCCESS)

    def _paginator(self, action_result, params, endpoint, key, offset, max_results):
        """
        Fetch all the results using pagination logic.

        :param action_result: object of ActionResult class
        :param params: params to be passed while calling the API
        :param endpoint: REST endpoint that needs to appended to the service address
        :param key: response key that needs to fetched
        :param offset: starting index of the results to be fetched
        :param max_results: maximum number of results to be fetched
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, successfully fetched results or None in case of failure
        """
        items_list = list()

        params['offset'] = offset
        params['limit'] = consts.BMCREMEDY_DEFAULT_PAGE_LIMIT

        while True:
            ret_val, items = self._make_rest_call_abstract(endpoint, action_result, params=params, method='get')

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            items_list.extend(items.get(key, []))

            # Max results fetched. Hence, exit the paginator.
            if max_results and len(items_list) >= max_results:
                return phantom.APP_SUCCESS, items_list[:max_results]

            # 1. Items fetched is less than the default page limit, which means there is no more data to be processed
            # 2. Next page link is not available in the response, which means there is no more data to be fetched from the server
            if (len(items.get(key, [])) < consts.BMCREMEDY_DEFAULT_PAGE_LIMIT) or (not items.get('_links', {}).get('next')):
                break

            params['offset'] += consts.BMCREMEDY_DEFAULT_PAGE_LIMIT

        return phantom.APP_SUCCESS, items_list

    def _list_tickets(self, param):
        """ Get list of incidents.

        :param param: includes limit: maximum number of incidents to return, query: additional parameters to query
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Getting optional parameters
        limit = param.get(consts.BMCREMEDY_JSON_LIMIT)
        query = param.get(consts.BMCREMEDY_JSON_QUERY)
        offset = param.get(consts.BMCREMEDY_JSON_OFFSET, consts.BMCREMEDY_DEFAULT_OFFSET)

        # Prepare request parameters
        # All incidents will be sorted in descending order based on their Last Modified date
        action_params = {"sort": "Last Modified Date.desc"}

        # Validate if 'limit' is positive integer
        ret_val, limit = self._validate_integer(action_result, limit, 'limit', allow_zero=True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_params['limit'] = limit

        if query:
            action_params['q'] = query

        # Integer validation for 'offset' parameter
        ret_val, offset = self._validate_integer(action_result, offset, 'offset', allow_zero=True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_params['offset'] = offset

        # make rest call
        response_status, response_data = self._paginator(
            action_result, action_params, consts.BMCREMEDY_LIST_TICKETS,
            'entries', offset, limit
        )

        # Something went wrong while executing request
        if phantom.is_fail(response_status):
            return action_result.get_status()

        for data in response_data:
            action_result.add_data(data)

        summary_data['total_tickets'] = len(response_data)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _set_status(self, param):
        """ This function modifies status of incident.

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        fields_param = {}

        # getting mandatory parameter
        incident_number = param[consts.BMCREMEDY_INCIDENT_NUMBER]

        fields_param['Status'] = param[consts.BMCREMEDY_JSON_STATUS]

        # Getting optional parameter
        if param.get("assignee_login_id"):
            fields_param["Assignee Login ID"] = param.get("assignee_login_id")

        if param.get("status_reason"):
            fields_param["Status_Reason"] = param.get("status_reason")

        optional_parameter_list = ["assigned_support_company", "assigned_support_organization", "assigned_group",
                                   "assignee", "resolution"]

        for parameter in optional_parameter_list:
            field_name = parameter.replace("_", " ").title()

            if param.get(parameter):
                fields_param[field_name] = param.get(parameter)

        fields_param = {"values": fields_param}

        # Getting update link for incident
        return_status, url = self._get_url(action_result, incident_number)

        if phantom.is_fail(return_status):
            self.debug_print(consts.BMCREMEDY_URL_NOT_FOUND)
            return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_URL_NOT_FOUND)

        if not url:
            return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_INCIDENT_NUMBER_NOT_FOUND)

        response_status, response_data = self._make_rest_call_abstract(str(url), action_result,
                                                                       data=json.dumps(fields_param), method='put')

        if phantom.is_fail(response_status):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, consts.BMCREMEDY_SET_STATUS_MESSAGE)

    def _add_comment(self, param):
        """ This function is used to add comment/work log to an incident.

        :param param: includes ID of incident to add comment
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        add_attachment_details_param = dict()
        attachment_data = dict()
        incident_number = param[consts.BMCREMEDY_INCIDENT_NUMBER]

        # List of optional parameters
        optional_parameters = {"comment": "Detailed Description", "view_access": "View Access",
                               "secure_work_log": "Secure Work Log"}

        # Adding mandatory parameters
        add_attachment_details_param.update({
            "Incident Number": incident_number,
            "Work Log Type": param[consts.BMCREMEDY_COMMENT_ACTIVITY_TYPE]
        })

        # Getting update link for incident
        return_status, url = self._get_url(action_result, incident_number)

        if phantom.is_fail(return_status):
            self.debug_print(consts.BMCREMEDY_URL_NOT_FOUND)
            return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_URL_NOT_FOUND)

        if not url:
            return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_INCIDENT_NUMBER_NOT_FOUND)

        # Adding optional parameters in 'fields'
        for key_param, api_key in optional_parameters.items():
            if param.get(key_param) and api_key not in add_attachment_details_param:
                add_attachment_details_param[str(api_key)] = str(param.get(key_param))

        attachment_data["values"] = add_attachment_details_param

        add_attachment_status, add_attachment_response_data = self._add_attachment(attachment_data, action_result)

        if phantom.is_fail(add_attachment_status):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, consts.BMCREMEDY_ADD_COMMENT_MESSAGE)

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of it's own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR
        """

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            'test_asset_connectivity': self._test_asset_connectivity,
            'create_ticket': self._create_ticket,
            'get_ticket': self._get_ticket,
            'list_tickets': self._list_tickets,
            'update_ticket': self._update_ticket,
            'set_status': self._set_status,
            'add_comment': self._add_comment
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping.keys():
            action_function = action_mapping[action]
            action_execution_status = action_function(param)

        return action_execution_status

    def finalize(self):
        """ This function gets called once all the param dictionary elements are looped over and no more handle_action
        calls are left to be made. It gives the AppConnector a chance to loop through all the results that were
        accumulated by multiple handle_action function calls and create any summary if required. Another usage is
        cleanup, disconnect from remote devices etc.
        """

        # save state
        self._state['token'] = self._token
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import sys
    import pudb

    pudb.set_trace()
    if len(sys.argv) < 2:
        print('No test json specified as input')
        exit(0)
    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = BmcremedyConnector()
        connector.print_progress_message = True
        return_value = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(return_value), indent=4))
    exit(0)
