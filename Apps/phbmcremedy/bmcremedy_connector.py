# File: bmcremedy_connector.py
# Copyright (c) 2017-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Standard library imports
import json
import re
import mimetools
import mimetypes
import requests

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

# Local imports
import bmcremedy_consts as consts

# Dictionary that maps each error code with its corresponding message
ERROR_RESPONSE_DICT = {
    consts.BMCREMEDY_REST_RESP_BAD_REQUEST: consts.BMCREMEDY_REST_RESP_BAD_REQUEST_MSG,
    consts.BMCREMEDY_REST_RESP_UNAUTHORIZED: consts.BMCREMEDY_REST_RESP_UNAUTHORIZED_MSG,
    consts.BMCREMEDY_REST_RESP_FORBIDDEN: consts.BMCREMEDY_REST_RESP_FORBIDDEN_MSG,
    consts.BMCREMEDY_REST_RESP_NOT_FOUND: consts.BMCREMEDY_REST_RESP_NOT_FOUND_MSG,
    consts.BMCREMEDY_REST_RESP_METHOD_NOT_ALLOWED: consts.BMCREMEDY_REST_RESP_METHOD_NOT_ALLOWED_MSG,
    consts.BMCREMEDY_REST_RESP_INTERNAL_SERVER_ERROR: consts.BMCREMEDY_REST_RESP_INTERNAL_SERVER_ERROR_MSG
}

# List containing http codes to be considered as success
SUCCESS_RESPONSE_CODES = [consts.BMCREMEDY_REST_RESP_TOKEN_SUCCESS, consts.BMCREMEDY_REST_RESP_CREATE_SUCCESS,
                          consts.BMCREMEDY_REST_RESP_NO_CONTENT]

# List of parameters that will be considered for adding attachment to an incident
add_attachment_params_list = ["Work Log Type", "View Access", "Secure Work Log", "Detailed Description"]


class RetVal3(tuple):
    def __new__(cls, val1, val2=None, val3=None):
        return tuple.__new__(RetVal3, (val1, val2, val3))


def encode_multipart_form_data(fields):
    """ Helper function used to encode multipart data with given request fields dictionary.

    :param fields: request fields dictionary
    :return: encoded request body and content type
    """

    boundary = '--{}'.format(mimetools.choose_boundary())

    body = ''

    for key, value in fields.iteritems():
        if isinstance(value, tuple):
            filename = value[0]
            content = value[1]
            body = "{}{}".format(body, consts.BMCREMEDY_ENCODE_TEMPLATE_FILE.format(
                boundary=boundary, name=str(key), value=str(content), filename=str(filename.encode('utf-8')),
                contenttype=str(mimetypes.guess_type(filename)[0] or 'application/octet-stream')
            ))
        else:
            body = "{}{}".format(body, consts.BMCREMEDY_ENCODE_TEMPLATE.format(boundary=boundary, name=str(key),
                                                                               value=json.dumps(value, indent=4)))

    body = "{}{}".format(body, '--{}--\n\r'.format(boundary))
    content_type = 'multipart/form-data; boundary={}'.format(boundary)

    return body, content_type


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

        self._token = self._state.get('token')

        # Return response_status
        return phantom.APP_SUCCESS

    def _check_login_status(self, action_result, response):

        if (not hasattr(response, 'headers')):
            return action_result.set_status(phantom.APP_ERROR, "Response missing headers, cannot determine success")

        x_ar_messages = response.headers.get('x-ar-messages')
        if (not x_ar_messages):
            return phantom.APP_SUCCESS

        # will need to parse the messages
        try:
            x_ar_messages = json.loads(x_ar_messages)
        except:
            return action_result.set_status(phantom.APP_ERROR, "Unable to process X-AR-Me")

        for curr_msg_dict in x_ar_messages:
            message_text = curr_msg_dict.get('messageText')
            if (not message_text):
                continue
            if ('login failed' in message_text.lower()):
                return action_result.set_status(phantom.APP_ERROR, "Login failed, please check your credentials")

        return (phantom.APP_SUCCESS)

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
        self._state['token'] = self._token = response_dict["content"]

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

        attachment_list = attachment_list.split(',')

        # At most, three attachments should be provided
        if len(attachment_list) > 3:
            self.debug_print(consts.BMCREMEDY_ATTACHMENT_LIMIT_EXCEED)
            return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_ATTACHMENT_LIMIT_EXCEED), None, None

        # Searching for file with vault id in current container
        files_array = (Vault.get_file_info(container_id=self.get_container_id()))
        for vault_id in attachment_list:
            file_found = False
            vault_id = vault_id.strip()
            for file_data in files_array:
                if file_data[consts.BMCREMEDY_JSON_VAULT_ID] == vault_id:
                    # Getting filename to use
                    filename.append(file_data['name'].encode('utf-8'))
                    # Reading binary data of file
                    file_obj.append(open(Vault.get_file_path(vault_id), 'rb').read())
                    file_found = True
                    break
            if not file_found:
                self.debug_print(consts.BMCREMEDY_UNKNOWN_VAULT_ID)

                return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_UNKNOWN_VAULT_ID), None, None

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
        if "entry" in attachment_data:
            # Encoding multipart data
            body, content_type = encode_multipart_form_data(attachment_data)
            data_params = 'Content-Type: {}\r\n'.format(content_type)
            data_params = "{}{}".format(data_params, "Content-Length: {}\r\n\r\n".format(str(len(body))))
            data_params = "{}{}".format(data_params, body)
            accept_headers = {'Content-Type': content_type}
        else:
            data_params = json.dumps(attachment_data)
            accept_headers = None

        # Create incident using given input parameters
        response_status, response_data = self._make_rest_call_abstract(consts.BMCREMEDY_COMMENT_ENDPOINT, action_result,
                                                                       data=data_params, method="post",
                                                                       accept_headers=accept_headers)

        if phantom.is_fail(response_status):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, response_data

    def _get_url(self, incident_number):
        """ Helper function returns the url for the set status and update ticket action.

        :param incident_number: ID of incident
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message) and url to be used
        """

        action_result = ActionResult()

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
                                 accept_headers=None):
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
        headers = {'Content-Type': 'application/json', "Authorization": "AR-JWT {}".format(self._token)}

        # Updating headers if Content-Type is 'multipart/formdata'
        if accept_headers:
            headers.update(accept_headers)

        # Make call
        rest_ret_code, response_data, response = self._make_rest_call(endpoint, intermediate_action_result, headers=headers,
                                                       params=params, data=data, method=method)

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

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="post"):
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

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            self.debug_print(consts.BMCREMEDY_ERR_API_UNSUPPORTED_METHOD.format(method=method))
            # Set the action_result status to error, the handler function will most probably return as is
            return RetVal3(action_result.set_status(phantom.APP_ERROR), response_data)
        except Exception as e:
            self.debug_print(consts.BMCREMEDY_EXCEPTION_OCCURRED)
            # Set the action_result status to error, the handler function will most probably return as is
            return RetVal3(action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_EXCEPTION_OCCURRED, e), response_data)

        try:
            response = request_func('{}{}'.format(self._base_url, endpoint), headers=headers, data=data, params=params,
                                    verify=self._verify_server_cert)
        except Exception as error:
            self.debug_print(consts.BMCREMEDY_REST_CALL_ERROR.format(error=str(error)))
            # Set the action_result status to error, the handler function will most probably return as is
            return RetVal3(action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_ERR_SERVER_CONNECTION, error.message), response_data)

        if response.status_code in ERROR_RESPONSE_DICT:
            self.debug_print(consts.BMCREMEDY_ERR_FROM_SERVER.format(status=response.status_code,
                                                                     detail=ERROR_RESPONSE_DICT[response.status_code]))

            response_data = {"content": response.content, "headers": response.headers}

            response_message = ""
            custom_error_message = ""
            if response_data and response_data.get('content'):
                try:
                    content_dict = json.loads(response_data.get("content"))[0]
                    if consts.BMCREMEDY_BLANK_PARAM_ERROR_SUBSTRING in content_dict.get('messageAppendedText'):
                        custom_error_message = consts.BMCREMEDY_CUSTOM_ERROR_MSG
                    response_message = 'messageText: {0}\nmessageAppendedText: {1}'. \
                        format(content_dict['messageText'], custom_error_message + content_dict['messageAppendedText'])
                except:
                    msg_string = consts.BMCREMEDY_ERR_JSON_PARSE.format(raw_text=response.text)
                    self.debug_print(msg_string)

            # Set the action_result status to error, the handler function will most probably return as is
            return RetVal3(action_result.set_status(phantom.APP_ERROR, '{0}\n{1}'.format(consts.BMCREMEDY_ERR_FROM_SERVER,
                                                                                 response_message),
                                            status=response.status_code,
                                            detail=ERROR_RESPONSE_DICT[response.status_code]), response_data)

        # Try parsing response, even in the case of an HTTP error the data might contain a json of details 'message'
        try:
            content_type = response.headers.get('content-type')
            if content_type and content_type.find('json') != -1:
                response_data = response.json()
            else:
                response_data = {"content": response.content, "headers": response.headers}
        except Exception as e:
            # response.text is guaranteed to be NON None, it will be empty, but not None
            msg_string = consts.BMCREMEDY_ERR_JSON_PARSE.format(raw_text=response.text)
            self.debug_print(msg_string)
            # Set the action_result status to error, the handler function will most probably return as is
            return RetVal3(action_result.set_status(phantom.APP_ERROR, msg_string, e), response_data)

        if response.status_code in SUCCESS_RESPONSE_CODES:
            return RetVal3(phantom.APP_SUCCESS, response_data, response)

        # See if an error message is present
        message = str(response_data.get('message', consts.BMCREMEDY_REST_RESP_OTHER_ERROR_MSG))
        self.debug_print(consts.BMCREMEDY_ERR_FROM_SERVER.format(status=response.status_code, detail=message))

        # Set the action_result status to error, the handler function will most probably return as is
        return RetVal3(action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_ERR_FROM_SERVER, status=response.status_code, detail=message), response_data)

    def _test_asset_connectivity(self, param):
        """ This function tests the connectivity of an asset with given credentials.

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        action_result = ActionResult()
        self.save_progress(consts.BMCREMEDY_TEST_CONNECTIVITY_MSG)
        self.save_progress("Configured URL: {}".format(self._base_url))

        response_status = self._generate_api_token(action_result)

        if phantom.is_fail(response_status):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, consts.BMCREMEDY_TEST_CONNECTIVITY_FAIL)
            return action_result.get_status()

        self.set_status_save_progress(phantom.APP_SUCCESS, consts.BMCREMEDY_TEST_CONNECTIVITY_PASS)

        return action_result.get_status()

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
        except Exception as e:
            self.debug_print(consts.BMCREMEDY_JSON_LOADS_ERROR.format(e))
            return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_JSON_LOADS_ERROR.format(e))

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
        for add_attachment_param in add_attachment_params_list:
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

        if not response_data["headers"].get("Location"):
            return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_LOCATION_NOT_FOUND)

        # Fetch url to get details of newly created incident
        get_incident_data = re.findall("(?:/api).*", response_data["headers"].get("Location"))[0]

        # Get details of newly created incident
        response_status, incident_response_data = self._make_rest_call_abstract(get_incident_data, action_result,
                                                                                method="get")

        if phantom.is_fail(response_status):
            return action_result.get_status()

        try:
            if not incident_response_data.get("values").get("Incident Number"):
                return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_INCIDENT_NUMBER_NOT_FOUND)

            summary_data["incident_id"] = incident_response_data["values"].get("Incident Number")

        except Exception as e:
            self.debug_print("Error while summarizing data: {}".format(str(e)))
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

        # Getting parameters that are related to adding attachment
        # fields_param may contain extra information apart from details of adding attachment. So getting information
        # about attachments and removing corresponding details from fields_param
        for add_attachment_param in add_attachment_params_list:
            if add_attachment_param in fields_param:
                add_attachment_details_param[add_attachment_param] = fields_param[add_attachment_param]
                fields_param.pop(add_attachment_param)

        # If incident details are to be updated apart from adding attachment, then update API will be called
        if fields_param:
            # Getting update link for incident
            return_status, update_link = self._get_url(incident_number)

            if phantom.is_fail(return_status):
                self.debug_print(consts.BMCREMEDY_URL_NOT_FOUND)
                return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_URL_NOT_FOUND)

            if not update_link:
                return action_result.set_status(phantom.APP_SUCCESS, consts.BMCREMEDY_INCIDENT_NUMBER_NOT_FOUND)

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

        # Prepare request parameters
        # All incidents will be sorted in descending order based on their Last Modified date
        action_params = {"sort": "Last Modified Date.desc"}

        if limit:
            # Validate if limit is positive integer
            if str(limit).isdigit() and int(limit) != 0:
                action_params['limit'] = limit
            else:
                self.debug_print(consts.BMCREMEDY_JSON_LIMIT_PARAM_ERROR)
                return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_JSON_LIMIT_PARAM_ERROR)

        if query:
            action_params['q'] = query

        response_status, response_data = self._make_rest_call_abstract(consts.BMCREMEDY_LIST_TICKETS, action_result,
                                                                       params=action_params, method='get')

        # Something went wrong while executing request
        if phantom.is_fail(response_status):
            return action_result.get_status()

        summary_data['total_tickets'] = len(response_data.get('entries'))
        action_result.add_data(response_data)

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
            fields_param["Assignee Login ID"] = param["assignee_login_id"]

        if param.get("status_reason"):
            fields_param["Status_Reason"] = param["status_reason"]

        optional_parameter_list = ["assigned_support_company", "assigned_support_organization", "assigned_group",
                                   "assignee", "resolution"]

        for parameter in optional_parameter_list:
            field_name = parameter.replace("_", " ").title()

            if param.get(parameter):
                fields_param[field_name] = param.get(parameter)

        fields_param = {"values": fields_param}

        # Getting update link for incident
        return_status, url = self._get_url(incident_number)

        if phantom.is_fail(return_status):
            self.debug_print(consts.BMCREMEDY_URL_NOT_FOUND)
            return action_result.set_status(phantom.APP_ERROR, consts.BMCREMEDY_URL_NOT_FOUND)

        if not url:
            return action_result.set_status(phantom.APP_SUCCESS, consts.BMCREMEDY_INCIDENT_NUMBER_NOT_FOUND)

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

        # List of optional parameters
        optional_parameters = {"comment": "Detailed Description", "view_access": "View Access",
                               "secure_work_log": "Secure Work Log"}

        # Get optional parameters
        attachment_list = param.get(consts.BMCREMEDY_JSON_VAULT_ID, '')

        if attachment_list:
            # Getting attachment related information
            vault_details_status, add_attachment_details_param, attachment_data = \
                self._provide_attachment_details(attachment_list, action_result)

            # Something went wrong while executing request
            if phantom.is_fail(vault_details_status):
                return action_result.get_status()

        # Adding mandatory parameters
        add_attachment_details_param.update({
            "Incident Number": param[consts.BMCREMEDY_INCIDENT_NUMBER],
            "Work Log Type": param[consts.BMCREMEDY_COMMENT_ACTIVITY_TYPE]
        })

        # Adding optional parameters in 'fields'
        for key_param, api_key in optional_parameters.iteritems():
            if param.get(key_param) and api_key not in add_attachment_details_param:
                add_attachment_details_param[str(api_key)] = str(param.get(key_param))

        if attachment_list:
            attachment_data["entry"] = {"values": add_attachment_details_param}
        else:
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
        print 'No test json specified as input'
        exit(0)
    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print json.dumps(in_json, indent=4)
        connector = BmcremedyConnector()
        connector.print_progress_message = True
        return_value = connector._handle_action(json.dumps(in_json), None)
        print json.dumps(json.loads(return_value), indent=4)
    exit(0)
