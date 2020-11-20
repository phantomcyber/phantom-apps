# File: smime_connector.py
# Copyright (c) 2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from smime_consts import *
import requests
import json
import os
import sys
from M2Crypto import BIO, Rand, SMIME, X509
from bs4 import UnicodeDammit


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class SmimeConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(SmimeConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

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

    def _sign(self, action_result, message):
        # Make a MemoryBuffer of the message.
        buf = BIO.MemoryBuffer(message)

        # Seed the random number generator with 1024 random bytes (8192 bits).
        Rand.rand_seed(os.urandom(1024))

        # Instantiate an SMIME object; set it up; sign the buffer.
        s = SMIME.SMIME()
        s.load_key_bio(BIO.MemoryBuffer(self._keys['private']),
                       BIO.MemoryBuffer(self._keys['public']))
        return s, s.sign(buf, SMIME.PKCS7_DETACHED)

    def _handle_sign_email(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        # message_body = bytes(str(param['message_body']).encode("utf-8"))
        try:
            message_body = bytes(self._handle_py_ver_compat_for_input_str(param['message_body']))
        except:
            return action_result.set_status(phantom.APP_ERROR, "Please verify the value of 'message_body' action parameter")

        # Optional values should use the .get() function
        # vault_id = param.get('vault_id', '')

        self.save_progress(SMIME_SIGN_PROGRESS_MSG)
        try:
            s, p7 = self._sign(action_result, message_body)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.save_progress(SMIME_SIGN_ERR_MSG.format(err=error_msg))
            return action_result.set_status(phantom.APP_ERROR, SMIME_SIGN_ERR_MSG.format(err=error_msg))

        # Recreate buf.
        try:
            buf = BIO.MemoryBuffer(message_body)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while creating MemoryBuffer of the message. {}".format(err))

        # Output p7 in mail-friendly format.
        try:
            out = BIO.MemoryBuffer()
            s.write(out, p7, buf)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while writing the message in mail-friendly format. {}".format(err))

        self.save_progress(SMIME_SIGN_OK_MSG)

        # Add the response into the data section
        try:
            action_result.add_data({
                'SMIME': {
                    'message': out.read()
                }
            })
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while adding data to the 'action_result'. {}".format(err))

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, SMIME_SIGN_OK_MSG)

    def _handle_encrypt_email(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        # message_body = bytes(str(param['message_body']).encode("utf-8"))
        try:
            message_body = bytes(self._handle_py_ver_compat_for_input_str(param['message_body']))
        except:
            return action_result.set_status(phantom.APP_ERROR, "Please verify the value of 'message_body' action parameter")

        self.save_progress(SMIME_ENCRYPT_PROGRESS_MSG)
        try:
            # Create a temporary buffer.
            tmp = BIO.MemoryBuffer(message_body)

            Rand.rand_seed(os.urandom(1024))

            # Instantiate an SMIME object.
            s = SMIME.SMIME()

            # Load target cert to encrypt the signed message to.
            x509 = X509.load_cert_string(self._keys['public'])
            sk = X509.X509_Stack()
            sk.push(x509)
            s.set_x509_stack(sk)

            # Set cipher: 3-key triple-DES in CBC mode.
            s.set_cipher(SMIME.Cipher('des_ede3_cbc'))

            # Encrypt the temporary buffer.
            p7 = s.encrypt(tmp)

        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.save_progress(SMIME_ENCRYPT_ERR_MSG.format(err=error_msg))
            return action_result.set_status(phantom.APP_ERROR, SMIME_ENCRYPT_ERR_MSG.format(err=error_msg))

        # Output p7 in mail-friendly format.
        try:
            out = BIO.MemoryBuffer()
            s.write(out, p7)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while writing the message in mail-friendly format. {}".format(err))

        self.save_progress(SMIME_ENCRYPT_OK_MSG)

        # Add the response into the data section
        try:
            action_result.add_data({
                'SMIME': {
                    'message': out.read()
                }
            })
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while adding data to the 'action_result'. {}".format(err))

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, SMIME_ENCRYPT_OK_MSG)

    def _handle_decrypt_email(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        # encrypted_message = bytes(
        #     str(param['encrypted_message']).encode("utf-8"))
        try:
            encrypted_message = bytes(self._handle_py_ver_compat_for_input_str(param['encrypted_message']))
        except:
            return action_result.set_status(phantom.APP_ERROR, "Please verify the value of 'encrypted_message' action parameter")

        self.save_progress(SMIME_DECRYPT_PROGRESS_MSG)

        try:
            buf = BIO.MemoryBuffer(encrypted_message)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while creating MemoryBuffer of the message. {}".format(err))

        # Instantiate an SMIME object.
        try:
            s = SMIME.SMIME()
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while instantiating SMime object. {}".format(err))

        # Load the data, verify it.
        try:
            # Load private key and cert.
            s.load_key_bio(BIO.MemoryBuffer(self._keys['private']),
                           BIO.MemoryBuffer(self._keys['public']))

            # Load the signed/encrypted data.
            p7, data = SMIME.smime_load_pkcs7_bio(buf)

            # After the above step, 'data' == None.
            # Decrypt p7. 'out' now contains a PKCS #7 signed blob.
            out = s.decrypt(p7)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            if "wrong content type" in err_msg:
                self.save_progress(SMIME_DECRYPT_ERR2_MSG)
                return action_result.set_status(phantom.APP_ERROR, SMIME_DECRYPT_ERR2_MSG)

            self.save_progress(SMIME_DECRYPT_ERR_MSG.format(err=err_msg))
            return action_result.set_status(phantom.APP_ERROR, SMIME_DECRYPT_ERR_MSG.format(err=err_msg))

        self.save_progress(SMIME_DECRYPT_OK_MSG)

        # Add the response into the data section
        try:
            action_result.add_data({
                'SMIME': {
                    'message': out
                }
            })
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while adding data to the 'action_result'. {}".format(err))

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, SMIME_DECRYPT_OK_MSG)

    def _handle_verify_email(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        # signed_message = bytes(str(param['signed_message']).encode("utf-8"))
        try:
            signed_message = bytes(self._handle_py_ver_compat_for_input_str(param['signed_message']))
        except:
            return action_result.set_status(phantom.APP_ERROR, "Please verify the value of 'signed_message' action parameter")

        self.save_progress(SMIME_VERIFY_PROGRESS_MSG)

        try:
            buf = BIO.MemoryBuffer(signed_message)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while creating MemoryBuffer of the message. {}".format(err))

        # Instantiate an SMIME object.
        try:
            s = SMIME.SMIME()
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while instantiating SMime object. {}".format(err))

        try:
            # Load the signer's cert.
            x509 = X509.load_cert_string(self._keys['public'])
            sk = X509.X509_Stack()
            sk.push(x509)
            s.set_x509_stack(sk)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.save_progress(SMIME_VERIFY_ERR_MSG.format(err=error_msg))
            return action_result.set_status(phantom.APP_ERROR, SMIME_VERIFY_ERR_MSG.format(err=error_msg))

        try:
            # Load the signer's CA cert. In this case, because the signer's
            # cert is self-signed, it is the signer's cert itself.
            st = X509.X509_Store()
            st.add_x509(x509)
            s.set_x509_store(st)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.save_progress(SMIME_VERIFY_ERR_MSG.format(err=error_msg))
            return action_result.set_status(phantom.APP_ERROR, SMIME_VERIFY_ERR_MSG.format(err=error_msg))

        # Load the data, verify it.
        try:
            p7, data = SMIME.smime_load_pkcs7_bio(buf)
            v = s.verify(p7, data)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            if "wrong content type" in error_msg:
                self.save_progress(SMIME_VERIFY_ERR2_MSG)
                return action_result.set_status(phantom.APP_ERROR, SMIME_VERIFY_ERR2_MSG)

            self.save_progress(SMIME_VERIFY_ERR_MSG.format(err=error_msg))
            return action_result.set_status(phantom.APP_ERROR, SMIME_VERIFY_ERR_MSG.format(err=error_msg))

        self.save_progress(SMIME_VERIFY_OK_MSG)

        try:
            # Add the response into the data section
            action_result.add_data({
                'SMIME': {
                    'message': v
                }
            })
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while adding data to the 'action_result'. {}".format(err))

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, SMIME_VERIFY_OK_MSG)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'sign_email':
            ret_val = self._handle_sign_email(param)
        elif action_id == 'encrypt_email':
            ret_val = self._handle_encrypt_email(param)
        elif action_id == 'decrypt_email':
            ret_val = self._handle_decrypt_email(param)
        elif action_id == 'verify_email':
            ret_val = self._handle_verify_email(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        config = self.get_config()

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version")

        # Load keys
        self._keys = {
            "private": self._handle_py_ver_compat_for_input_str(config.get('private_key')),
            "public": self._handle_py_ver_compat_for_input_str(config.get('public_key'))
        }

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
            login_url = SmimeConnector._get_phantom_base_url() + '/login'
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
            r2 = requests.post(login_url,
                               verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SmimeConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
