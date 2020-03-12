# File: smime_connector.py
# Copyright (c) 2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
# from phantom.vault import Vault

# Usage of the consts file is recommended
from smime_consts import *
import requests
import json
import os
# import tempfile
from M2Crypto import BIO, Rand, SMIME, X509


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
        message_body = param['message_body']

        # Optional values should use the .get() function
        # vault_id = param.get('vault_id', '')

        self.save_progress(SMIME_SIGN_PROGRESS_MSG)
        try:
            s, p7 = self._sign(action_result, message_body)
        except Exception as e:
            self.save_progress(SMIME_SIGN_ERR_MSG.format(err=str(e)))
            return action_result.set_status(phantom.APP_ERROR, SMIME_SIGN_ERR_MSG.format(err=str(e)))

        # Recreate buf.
        buf = BIO.MemoryBuffer(message_body)

        # Output p7 in mail-friendly format.
        out = BIO.MemoryBuffer()
        s.write(out, p7, buf)

        self.save_progress(SMIME_SIGN_OK_MSG)

        # Add the response into the data section
        action_result.add_data({
            'SMIME': {
                'message': out.read()
            }
        })

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
        message_body = param['message_body']

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
            self.save_progress(SMIME_ENCRYPT_ERR_MSG.format(err=str(e)))
            return action_result.set_status(phantom.APP_ERROR, SMIME_ENCRYPT_ERR_MSG.format(err=str(e)))

        # Output p7 in mail-friendly format.
        out = BIO.MemoryBuffer()
        s.write(out, p7)

        self.save_progress(SMIME_ENCRYPT_OK_MSG)

        # Add the response into the data section
        action_result.add_data({
            'SMIME': {
                'message': out.read()
            }
        })

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
        encrypted_message = param['encrypted_message']

        self.save_progress(SMIME_DECRYPT_PROGRESS_MSG)

        buf = BIO.MemoryBuffer(encrypted_message)

        # Instantiate an SMIME object.
        s = SMIME.SMIME()

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
            if "wrong content type" in str(e):
                self.save_progress(SMIME_DECRYPT_ERR2_MSG)
                return action_result.set_status(phantom.APP_ERROR, SMIME_DECRYPT_ERR2_MSG)

            self.save_progress(SMIME_DECRYPT_ERR_MSG.format(err=str(e)))
            return action_result.set_status(phantom.APP_ERROR, SMIME_DECRYPT_ERR_MSG.format(err=str(e)))

        self.save_progress(SMIME_DECRYPT_OK_MSG)

        # Add the response into the data section
        action_result.add_data({
            'SMIME': {
                'message': out
            }
        })

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
        signed_message = param['signed_message']

        self.save_progress(SMIME_VERIFY_PROGRESS_MSG)

        buf = BIO.MemoryBuffer(signed_message)

        # Instantiate an SMIME object.
        s = SMIME.SMIME()

        # Load the signer's cert.
        x509 = X509.load_cert_string(self._keys['public'])
        sk = X509.X509_Stack()
        sk.push(x509)
        s.set_x509_stack(sk)

        # Load the signer's CA cert. In this case, because the signer's
        # cert is self-signed, it is the signer's cert itself.
        st = X509.X509_Store()
        # NOTE: Official code expects to have a file location, not the file content!
        # Src: https://gitlab.com/m2crypto/m2crypto/blob/master/M2Crypto/X509.py
        # st.load_info(self._keys['public'])
        st.add_x509(x509)
        s.set_x509_store(st)

        # Load the data, verify it.
        try:
            p7, data = SMIME.smime_load_pkcs7_bio(buf)
            v = s.verify(p7, data)
        except Exception as e:
            if "wrong content type" in str(e):
                self.save_progress(SMIME_VERIFY_ERR2_MSG)
                return action_result.set_status(phantom.APP_ERROR, SMIME_VERIFY_ERR2_MSG)

            self.save_progress(SMIME_VERIFY_ERR_MSG.format(err=str(e)))
            return action_result.set_status(phantom.APP_ERROR, SMIME_VERIFY_ERR_MSG.format(err=str(e)))

        self.save_progress(SMIME_VERIFY_OK_MSG)

        # Add the response into the data section
        action_result.add_data({
            'SMIME': {
                'message': v
            }
        })

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

        # Load keys
        self._keys = {
            "private": str(config.get('private_key')),
            "public": str(config.get('public_key'))
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
            r2 = requests.post("https://127.0.0.1/login",
                               verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platform. Error: " + str(e))
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
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
