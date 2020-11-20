# File: hashicorp_vault_connector.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

import phantom.app as phantom
from phantom.action_result import ActionResult
import json
import sys
import hvac
from bs4 import UnicodeDammit
from hashicorp_vault_consts import *
import urllib.parse


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class AppConnectorHashicorpVault(phantom.BaseConnector):
    def __init__(self):
        super(AppConnectorHashicorpVault, self).__init__()
        return

    def initialize(self):
        self._state = self.load_state()

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version.")

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.
        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """

        try:
            if input_str and self._python_version == 2:
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
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

    def _get_token(self):
        self.save_progress('Getting token from asset configuration..._get_token()')
        config = self.get_config()
        token = config['vault_token']
        return token

    def _get_url(self):
        self.save_progress('Getting vault URL from asset configuration..._get_url()')
        config = self.get_config()
        url = config['vault_url']
        return url

    def _get_mountpoint(self):
        self.save_progress('Getting vault mountpoint from asset configuration..._get_mountpoint()')
        config = self.get_config()
        mountpoint = config['vault_mountpoint']
        return mountpoint

    def _create_vault_client(self, action_result):
        url = self._get_url()
        token = self._get_token()

        if url and token:
            try:
                vault_client = hvac.Client(url=url, token=token)
                return RetVal(action_result.set_status(phantom.APP_SUCCESS, 'Successfully created Hashicorp Vault Client'), vault_client)
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                err = urllib.parse.unquote(err)
                return RetVal(
                    action_result.set_status(
                        phantom.APP_ERROR,
                        "Error in getting the Hashicorp Vault Client. {0}".format(err)
                    ), None
                )
        else:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error in fetching url and token"), None)

    def _test_connectivity(self, action_result):
        ret_val, hvac_client = self._create_vault_client(action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if hvac_client:
            try:
                is_authenticated = hvac_client.is_authenticated()
                if is_authenticated:
                    self.save_progress('Successfully connected to Hashicorp vault with given credentials')
                    return action_result.set_status(phantom.APP_SUCCESS, 'Successfully connected to Hashicorp Vault')
                else:
                    self.save_progress('Failed to connect to Hashicorp vault with given credentials')
                    return action_result.set_status(phantom.APP_ERROR, 'Failed to connect to Hashicorp Vault')
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                err = urllib.parse.unquote(err)
                return action_result.set_status(phantom.APP_ERROR, 'Error in authenticating Hashicorp Vault Client. {0}'.format(err))
        else:
            self.save_progress('Failed to create Hashicorp Vault client')
            return action_result.set_status(phantom.APP_ERROR, 'Failed to create Hashicorp Vault client')

    def _set_secret(self, param, action_result):
        ret_val, hvac_client = self._create_vault_client(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        mountpoint = self._get_mountpoint()
        path = param.get('location')
        secret = param.get('secret_json')
        self.save_progress(secret)
        try:
            secret = json.loads(secret)
            try:
                create_response = hvac_client.secrets.kv.v2.create_or_update_secret(mount_point=mountpoint, path=path, secret=secret)
                if create_response:
                    self.save_progress("Successfully added the secret")
                    action_result.add_data({"succeeded": True})
                    return action_result.set_status(phantom.APP_SUCCESS, 'Successfully added the secret')
                else:
                    self.save_progress("Failed to add the secret to Hashicorp Vault")
                    return action_result.set_status(phantom.APP_ERROR, "Failed to add the secret to Hashicorp Vault")
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                err = urllib.parse.unquote(err)
                self.save_progress("Error occurred while storing the secret in Hashicorp vault. {}".format(err))
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while storing the secret in Hashicorp vault. {}".format(err))

        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.save_progress("Please verify 'secret_json' action parameter. {}".format(err))
            return action_result.set_status(phantom.APP_ERROR, "Please verify 'secret_json' action parameter. {}".format(err))

    def _get_secret(self, param, action_result):
        ret_val, hvac_client = self._create_vault_client(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        mountpoint = self._get_mountpoint()
        path = param.get('location')
        try:
            read_response = hvac_client.secrets.kv.v2.read_secret_version(mount_point=mountpoint, path=path)
            if read_response:
                try:
                    secret_value = read_response['data']['data']
                    if secret_value:
                        self.save_progress("Secret value retrieved successfully")
                        action_result.add_data({"succeeded": True, "secret_value": secret_value})
                        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully retrieved secret value')
                    else:
                        self.save_progress("No secret value retrieved from Hashicorp Vault for the specified path")
                        return action_result.set_status(phantom.APP_ERROR, "No secret value retrieved from Hashicorp Vault for the specified path")
                except Exception as e:
                    err = self._get_error_message_from_exception(e)
                    return action_result.set_status(phantom.APP_ERROR, "Error in getting secret value from the API response. {}".format(err))
            else:
                self.save_progress("Error in retrieving secret value from Hashicorp Vault")
                return action_result.set_status(phantom.APP_ERROR, "Error in retrieving secret value from Hashicorp Vault")
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            err = urllib.parse.unquote(err)
            self.save_progress("Error in retrieving secret value from Hashicorp Vault. {}".format(err))
            return action_result.set_status(phantom.APP_ERROR, "Error in retrieving secret value from Hashicorp Vault. {}".format(err))

    def _list_secrets(self, param, action_result):
        ret_val, hvac_client = self._create_vault_client(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        mountpoint = self._get_mountpoint()
        path = param.get('location')
        try:
            list_secrets = hvac_client.secrets.kv.v2.list_secrets(mount_point=mountpoint, path=path)
            if list_secrets:
                try:
                    secrets = list_secrets['data']['keys']
                    if secrets:
                        self.save_progress("Secrets retrieved successfully")
                        action_result.add_data({"succeeded": True, "secret_values": secrets})
                        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully retrieved secret values')
                    else:
                        self.save_progress("No secrets retrieved from Hashicorp Vault for the specified path")
                        return action_result.set_status(phantom.APP_ERROR, "No secrets retrieved from Hashicorp Vault for the specified path")
                except Exception as e:
                    err = self._get_error_message_from_exception(e)
                    return action_result.set_status(phantom.APP_ERROR, "Error in getting secrets from the API response. {}".format(err))
            else:
                self.save_progress("Error in retrieving secrets from Hashicorp Vault")
                return action_result.set_status(phantom.APP_ERROR, "Error in retrieving secrets from Hashicorp Vault")
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            err = urllib.parse.unquote(err)
            self.save_progress("Error in retrieving secrets from Hashicorp Vault. {}".format(err))
            return action_result.set_status(phantom.APP_ERROR, "Error in retrieving secrets from Hashicorp Vault. {}".format(err))

    def handle_action(self, param):
        action = self.get_action_identifier()
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = phantom.APP_SUCCESS

        if action == ACTION_ID_SET_SECRET:
            ret_val = self._set_secret(param, action_result)

        if action == ACTION_ID_GET_SECRET:
            ret_val = self._get_secret(param, action_result)

        if action == ACTION_ID_LIST_SECRETS:
            ret_val = self._list_secrets(param, action_result)

        if action == ACTION_ID_TEST_ASSET_CONNECTIVITY:
            ret_val = self._test_connectivity(action_result)

        return ret_val


if __name__ == '__main__':
    import pudb
    pudb.set_trace()
    if len(sys.argv) < 2:
        print('No test json specified as input')
        exit(0)
    with open(sys.argv[1]) as (f):
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = AppConnectorHashicorpVault()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))
    exit(0)
