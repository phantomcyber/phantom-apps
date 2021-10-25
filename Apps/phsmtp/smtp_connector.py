# File: smtp_connector.py
#
# Copyright (c) 2014-2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault
import phantom.utils as ph_utils
import phantom.rules as ph_rules

# THIS Connector imports
from smtp_consts import *

import mimetypes
import smtplib
import os
import json
import sys
import re
from email import encoders
from email import message_from_file
from email import message_from_string
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.message import MIMEMessage
from email.mime.multipart import MIMEMultipart
from bs4 import BeautifulSoup, UnicodeDammit


class SmtpConnector(BaseConnector):

    # actions supported by this script
    ACTION_ID_SEND_EMAIL = "send_email"

    def __init__(self):

        # Call the BaseConnectors init first
        super(SmtpConnector, self).__init__()
        self._smtp_conn = None
        self.invalid_vault_ids = list()

    def _validate_email(self, input_data):

        # validations are always tricky things, making it 100% foolproof, will take a
        # very complicated regex, even multiple regexes and each could lead to a bug that
        # will invalidate the input (at a customer site), leading to actions being stopped from carrying out.
        # So keeping things as simple as possible here. The SMTP server will hopefully do a good job of
        # validating it's input, any errors that are sent back to the app will get propagated to the user.

        emails = []

        # First work on the comma as the separator
        if (',' in input_data):
            emails = input_data.split(',')
        elif(';' in input_data):
            emails = input_data.split(';')

        for email in emails:
            if (not ph_utils.is_email(email.strip())):
                return False
        return True

    def initialize(self):

        self._smtp_conn = None

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version")

        try:
            status_code = self._connect_to_server()
        except Exception as e:
            return self._parse_connection_error(e)

        self.set_validator('email', self._validate_email)

        return status_code

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

    def _handle_py_ver_compat_for_sendemail(self, root_data_str):
        """
        This method converts the provided email message's as_string() into Python v2 and v3 compatible string and bytes string version respectively.
        :param root_data_str: Input email message's as_string() to be processed
        :return: root_data_str (Processed email message's as_string() based on following logic 'original root_data_str - Python 2; encoded bytes format root_data_str - Python 3')
        """

        # UnicodeDammit(msg.as_string()).unicode_markup.encode("utf-8")
        # Above fix works for both Python v2 and Python v3 and should not be changed or
        # changed only after thorough testing on both the Python v2 and v3 versions.
        # This fix is based on solutions provided on the Python bug tracker portal issue
        # raised by us for sendemail not working for Unicode Characters for Python v3
        # Bug Link - https://bugs.python.org/issue41023
        try:
            if self._python_version != 2:
                root_data_str = UnicodeDammit(root_data_str).unicode_markup.encode('utf-8')
        except:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the email message string")

        return root_data_str

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = ERR_CODE_UNAVAILABLE
        error_msg = ERR_MSG_UNAVAILABLE

        try:
            if hasattr(e, 'args'):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except:
            pass

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = TYPE_ERR_MSG
        except:
            pass

        try:
            error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
        except:
            self.debug_print("Error occurred while parsing the error message")
            error_text = PARSE_ERR_MSG

        return error_text

    def _parse_connection_error(self, e):
        """An error has already occurred"""

        message = ''
        exception_message = ''

        try:
            config = self.get_config()
            exception_message = self._get_error_message_from_exception(e)
            port_message = ' Please try without specifying the port. ' if (config.get(SMTP_JSON_PORT)) else ' '

            if (config[SMTP_JSON_SSL_CONFIG] == SSL_CONFIG_SSL) and ('ssl.c' in exception_message):
                message = "{0}.\r\n{1}{2}Error Text: {3}".format(SMTP_ERR_SMTP_CONNECT_TO_SERVER, SMTP_ERR_SSL_CONFIG_SSL, port_message, exception_message)
                return self.set_status(phantom.APP_ERROR, message)

            if (config[SMTP_JSON_SSL_CONFIG] == SSL_CONFIG_STARTTLS) and ('unexpectedly close' in exception_message):
                message = "{0}.\r\n{1}{2}Error Text:{3}".format(SMTP_ERR_SMTP_CONNECT_TO_SERVER, SMTP_ERR_STARTTLS_CONFIG, port_message, exception_message)
                return self.set_status(phantom.APP_ERROR, message)

        except:
            pass

        return self.set_status(phantom.APP_ERROR, "{} {}".format(SMTP_ERR_SMTP_CONNECT_TO_SERVER, exception_message))

    def _cleanup(self):

        if (self._smtp_conn):
            self._smtp_conn.quit()
            self._smtp_conn = None

    def handle_exception(self, e):

        self._cleanup()

    def _connect_to_server(self):

        config = self.get_config()

        self._smtp_conn = None
        server = config[phantom.APP_JSON_SERVER]

        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, server)

        # default the ssl config to non SSL i.e. either None or StartTLS
        func_to_use = getattr(smtplib, 'SMTP')

        # Get the SSL config to use
        ssl_config = config.get(SMTP_JSON_SSL_CONFIG, SSL_CONFIG_STARTTLS)

        # if it is SSL, (not None or StartTLS) then the function to call is different
        if (ssl_config == SSL_CONFIG_SSL):
            func_to_use = getattr(smtplib, 'SMTP_SSL')

        # use the port if specified
        if (SMTP_JSON_PORT in config):
            self._smtp_conn = func_to_use(server, str(config[SMTP_JSON_PORT]))
        else:
            self._smtp_conn = func_to_use(server)

        self._smtp_conn.ehlo()

        # Use the StartTLS command if the config was set to StartTLS
        if (self._smtp_conn.has_extn('STARTTLS') and (ssl_config == SSL_CONFIG_STARTTLS)):
            self._smtp_conn.starttls()

        self._smtp_conn.ehlo()

        if (phantom.APP_JSON_PASSWORD in config) and (phantom.APP_JSON_USERNAME in config):
            if self._smtp_conn.has_extn('AUTH'):
                self._smtp_conn.login(config[phantom.APP_JSON_USERNAME], config[phantom.APP_JSON_PASSWORD])
        else:
            self.save_progress(SMTP_MSG_SKIP_AUTH_NO_USERNAME_PASSWORD)

        self.save_progress(SMTP_SUCC_SMTP_CONNECTED_TO_SERVER)

        return phantom.APP_SUCCESS

    def _attach_bodies(self, outer, body, action_result, message_encoding):

        # first attach the plain if possible
        try:
            soup = BeautifulSoup(body)
            text = soup.get_text()

            # need to decode/encode for utf-8 emails with html
            if message_encoding == 'utf-8':
                # text = text.decode('utf-8')
                text = self._handle_py_ver_compat_for_input_str(text)
                part_plain = MIMEText(text, 'plain', 'utf-8')
            else:
                part_plain = MIMEText(text, 'plain')

            outer.attach(part_plain)
        except Exception as e:
            self.debug_print("Error in converting html body to text {}".format(self._get_error_message_from_exception(e)))

        try:
            # lastly attach html
            if message_encoding == 'utf-8':
                body = self._handle_py_ver_compat_for_input_str(body)
                part_html = MIMEText(body, 'html', 'utf-8')
            else:
                part_html = MIMEText(body, 'html')

            outer.attach(part_html)
        except Exception as e:
            self.debug_print("Error while attaching html body to outer {}".format(self._get_error_message_from_exception(e)))

        return phantom.APP_SUCCESS

    def _add_attachments(self, outer, attachments, action_result, message_encoding):

        if (not attachments):
            return phantom.APP_SUCCESS

        for attachment_vault_id in attachments:

            if self.get_container_id() == '0':

                if '.pdf' not in attachment_vault_id:
                    return action_result.set_status(phantom.APP_ERROR, SMTP_ERR_SMTP_SEND_EMAIL)

                if hasattr(Vault, "get_phantom_home"):
                    report_dir_pre_4_0 = '{0}/www/reports'.format(self.get_phantom_home())
                    report_dir_post_4_0 = '{0}/vault/reports'.format(self.get_phantom_home())
                else:
                    report_dir_pre_4_0 = '/opt/phantom/www/reports'
                    report_dir_post_4_0 = '/opt/phantom/vault/reports'

                filename = ''
                for report_dir in (report_dir_post_4_0, report_dir_pre_4_0):
                    test_filename = os.path.join(report_dir, attachment_vault_id)
                    test_filename = os.path.abspath(test_filename)

                    if os.path.isfile(test_filename):
                        filename = test_filename
                        break

                is_valid_path = filename.startswith(report_dir_pre_4_0) or filename.startswith(report_dir_post_4_0)

                if not filename or not is_valid_path:
                    return action_result.set_status(phantom.APP_ERROR, SMTP_ERR_SMTP_SEND_EMAIL)

                with open(filename, 'rb') as fp:
                    msg = MIMEBase('application', 'pdf')
                    msg.set_payload(fp.read())

                filename = os.path.basename(filename)
                # handling ugly file names that are of the format "report_type__id-X__ts-<timestamp>.pdf", where 'X' is any number
                if '__' in filename:
                    pieces = filename.split('__')
                    if len(pieces) == 3:
                        filename = '{}_{}'.format(pieces[0], pieces[2])  # get rid of __id_x__

                # Encode the payload using Base64
                encoders.encode_base64(msg)
            else:

                try:
                    _, _, vault_meta_info = ph_rules.vault_info(container_id=self.get_container_id(), vault_id=attachment_vault_id)
                    if not vault_meta_info:
                        _, _, vault_meta_info = ph_rules.vault_info(vault_id=attachment_vault_id)
                        if not vault_meta_info:
                            self.invalid_vault_ids.append(attachment_vault_id)
                            continue
                    vault_meta_info = list(vault_meta_info)
                except:
                    self.invalid_vault_ids.append(attachment_vault_id)
                    continue

                # Check if we have any results
                if (len(vault_meta_info) == 0):
                    continue

                # pick up the first one, they all point to the same file
                vault_meta_info = vault_meta_info[0]

                attachment_path = vault_meta_info['name']
                file_path = vault_meta_info['path']

                # Guess the content type based on the file's extension.  Encoding
                # will be ignored, although we should check for simple things like
                # gzip'd or compressed files.
                filename = os.path.basename(attachment_path)
                ctype, encoding = mimetypes.guess_type(attachment_path)
                if ctype is None or encoding is not None:
                    # No guess could be made, or the file is encoded (compressed), so
                    # use a generic bag-of-bits type.
                    ctype = 'application/octet-stream'
                maintype, subtype = ctype.split('/', 1)
                try:
                    if maintype == 'text':
                        fp = open(file_path)
                        # Note: we should handle calculating the charset
                        msg = MIMEText(fp.read(), _subtype=subtype)
                        fp.close()
                    elif maintype == 'message':
                        fp = open(file_path)
                        base_msg = message_from_file(fp)
                        msg = MIMEMessage(base_msg, _subtype=subtype)
                        fp.close()
                    elif maintype == 'image':
                        fp = open(file_path, 'rb')
                        msg = MIMEImage(fp.read(), _subtype=subtype)
                        fp.close()
                    else:
                        fp = open(file_path, 'rb')
                        msg = MIMEBase(maintype, subtype)
                        msg.set_payload(fp.read())
                        fp.close()
                        # Encode the payload using Base64
                        encoders.encode_base64(msg)
                except Exception as e:
                    return action_result.set_status(phantom.APP_ERROR, self._get_error_message_from_exception(e))

            # if using utf-8 encode the filename of the attachment as well
            if message_encoding == 'utf-8':
                filename = self._handle_py_ver_compat_for_input_str(filename)

            # Set the filename parameter
            msg.add_header('Content-Disposition', 'attachment', filename=filename)
            outer.attach(msg)

        return phantom.APP_SUCCESS

    def _is_html(self, body):

        # first lower it
        body_lower = body.lower()
        if re.match(r"^<!doctype\s+html.*?>", body_lower) or re.match(r"^<html.*?>", body_lower):
            return True
        return False

    def _send_email(self, param, action_result):

        # username = self.get_config()[phantom.APP_JSON_USERNAME]
        config = self.get_config()

        # Derive 'from' email address
        sender_address = config.get('sender_address', config.get(phantom.APP_JSON_USERNAME))
        email_from = param.get(SMTP_JSON_FROM, sender_address)

        encoding = config.get(SMTP_ENCODING, False)
        smtputf8 = config.get(SMTP_ALLOW_SMTPUTF8, False)
        body = param[SMTP_JSON_BODY]

        if not email_from:
            return action_result.set_status(phantom.APP_ERROR, "Error: failed to get email sender")

        if encoding:
            message_encoding = 'utf-8'
        else:
            message_encoding = 'ascii'

        outer = None
        attachments = None

        if(SMTP_JSON_ATTACHMENTS in param):
            attachments = self._handle_py_ver_compat_for_input_str(param[SMTP_JSON_ATTACHMENTS])
            attachments = [x.strip() for x in attachments.split(",")]
            attachments = list(filter(None, attachments))

        try:
            if (self._is_html(body)):
                outer = MIMEMultipart('alternative')
                self._attach_bodies(outer, body, action_result, message_encoding)
            elif(attachments):
                # it is not html, but has attachments
                outer = MIMEMultipart()
                msg = MIMEText(param[SMTP_JSON_BODY], 'plain', message_encoding)
                outer.attach(msg)
            else:
                outer = MIMEText(param[SMTP_JSON_BODY], 'plain', message_encoding)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "{0} Error message: {1}".format(SMTP_UNICODE_ERROR_MSG, self._get_error_message_from_exception(e)))

        if SMTP_JSON_HEADERS in param:
            try:
                headers = json.loads(param[SMTP_JSON_HEADERS])
                if not isinstance(headers, dict):
                    raise Exception
                try:
                    for header, value in headers.iteritems():
                        header = self._handle_py_ver_compat_for_input_str(header)
                        value = self._handle_py_ver_compat_for_input_str(value)
                        outer[header] = value
                except:
                    for header, value in headers.items():
                        outer[header] = value
            except Exception:
                # Break and return error if headers is not a correctly formatted dict.
                return action_result.set_status(phantom.APP_ERROR, SMTP_ERR_PARSE_HEADERS.format(self._handle_py_ver_compat_for_input_str(param[SMTP_JSON_HEADERS])))

        to_comma_sep_list = self._handle_py_ver_compat_for_input_str(param[SMTP_JSON_TO])
        cc_comma_sep_list = param.get(SMTP_JSON_CC, None)
        bcc_comma_sep_list = param.get(SMTP_JSON_BCC, None)

        if (SMTP_JSON_SUBJECT in param):
            outer['Subject'] = param[SMTP_JSON_SUBJECT]
            action_result.update_param({SMTP_JSON_SUBJECT: param[SMTP_JSON_SUBJECT]})

        outer['From'] = email_from
        action_result.update_param({SMTP_JSON_FROM: outer['From']})

        to_list = [x.strip() for x in to_comma_sep_list.split(",")]
        to_list = list(filter(None, to_list))
        outer['To'] = ", ".join(to_list)

        if cc_comma_sep_list:
            cc_comma_sep_list = self._handle_py_ver_compat_for_input_str(cc_comma_sep_list)
            cc_list = [x.strip() for x in cc_comma_sep_list.split(",")]
            cc_list = list(filter(None, cc_list))
            to_list.extend(cc_list)
            outer['CC'] = ",".join(cc_list)

        if bcc_comma_sep_list:
            bcc_comma_sep_list = self._handle_py_ver_compat_for_input_str(bcc_comma_sep_list)
            bcc_list = [x.strip() for x in bcc_comma_sep_list.split(",")]
            bcc_list = list(filter(None, bcc_list))
            to_list.extend(bcc_list)

        self._add_attachments(outer, attachments, action_result, message_encoding)

        try:
            # Provided mail_options=["SMTPUTF8"], to allow Unicode characters for py3 in to_list parameter
            # This will ensure that the to_list gets encoded with 'utf-8' and not the default encoding which is 'ascii'
            mail_options = list()
            if smtputf8:
                mail_options.append("SMTPUTF8")
            self._smtp_conn.sendmail(email_from, to_list, outer.as_string(), mail_options=mail_options)
        except UnicodeEncodeError:
            return action_result.set_status(phantom.APP_ERROR, "{} {}".format(SMTP_ERR_SMTP_SEND_EMAIL, SMTP_ERR_SMTPUTF8_CONFIG))
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "{} {}".format(SMTP_ERR_SMTP_SEND_EMAIL, self._get_error_message_from_exception(e)))

        if self.invalid_vault_ids:
            return action_result.set_status(phantom.APP_SUCCESS, "{}. The following attachments are invalid and were not sent: {}".format(
                SMTP_SUCC_SMTP_EMAIL_SENT, ", ".join(self.invalid_vault_ids)))

        return action_result.set_status(phantom.APP_SUCCESS, SMTP_SUCC_SMTP_EMAIL_SENT)

    def _handle_send_email(self, param, action_result=None):

        if (action_result is None):
            action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            status_code = self._send_email(param, action_result)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "{} {}".format(SMTP_ERR_SMTP_SEND_EMAIL, self._get_error_message_from_exception(e)))

        return status_code

    def _test_asset_connectivity(self, param):

        # There could be multiple ways to configure an SMTP server.
        # Even a username and password could be optional.
        # So the best way to test connectivity is to send an email.

        action_result = self.add_action_result(ActionResult(dict(param)))

        config = self.get_config()

        if (phantom.APP_JSON_USERNAME not in config) or (phantom.APP_JSON_PASSWORD not in config):
            # There is nothing else that we do here. If initialize(...) has succeeded (it must have, else we wont get called)
            # then the connection is fine
            self.save_progress(SMTP_SUCC_CONNECTIVITY_TEST)
            return action_result.set_status(phantom.APP_SUCCESS, SMTP_SUCC_CONNECTIVITY_TEST)

        param = {
                SMTP_JSON_TO: (config.get('sender_address') or config[phantom.APP_JSON_USERNAME]),
                SMTP_JSON_FROM: (config.get('sender_address') or config[phantom.APP_JSON_USERNAME]),
                SMTP_JSON_SUBJECT: "Test SMTP config",
                SMTP_JSON_BODY: "This is a test mail, sent by the Phantom device,\nto test connectivity to the SMTP Asset."}

        self.debug_print(param, param)

        self.save_progress(SMTP_SENDING_TEST_MAIL)
        if (phantom.is_fail(self._handle_send_email(param, action_result))):
            self.debug_print("connect failed")
            self.save_progress("Error message: {}".format(self._handle_py_ver_compat_for_input_str(action_result.get_message())))
            self.save_progress(SMTP_ERR_CONNECTIVITY_TEST)
            return action_result.set_status(phantom.APP_ERROR, SMTP_ERR_CONNECTIVITY_TEST)

        self.save_progress(SMTP_DONE)

        self.debug_print("connect passed")
        self.save_progress(SMTP_SUCC_CONNECTIVITY_TEST)
        return action_result.set_status(phantom.APP_SUCCESS, SMTP_SUCC_CONNECTIVITY_TEST)

    def html_to_text(self, html):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        text = soup.get_text(separator=" ")
        return text

    def _handle_send_htmlemail(self, param):  # noqa: C901

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(param))

        config = self.get_config()

        # Derive 'from' email address
        sender_address = config.get('sender_address', config.get(phantom.APP_JSON_USERNAME))
        email_from = param.get(SMTP_JSON_FROM, sender_address)

        email_to = self._handle_py_ver_compat_for_input_str(param['to'])
        email_cc = self._handle_py_ver_compat_for_input_str(param.get('cc'))
        email_bcc = self._handle_py_ver_compat_for_input_str(param.get('bcc'))
        # Filter method returns a Filter object on Python v3 and a List on Python v2
        # So, to maintain the uniformity the Filter object has been explicitly type casted to List
        email_to = [x.strip() for x in email_to.split(",")]
        email_to = list(filter(None, email_to))

        if email_cc:
            email_cc = [x.strip() for x in email_cc.split(",")]
            email_cc = list(filter(None, email_cc))

        if email_bcc:
            email_bcc = [x.strip() for x in email_bcc.split(",")]
            email_bcc = list(filter(None, email_bcc))

        email_subject = param.get('subject')
        email_headers = param.get('headers')
        email_html = param['html_body']
        email_text = param.get('text_body')
        attachment_json = param.get('attachment_json')

        encoding = config.get(SMTP_ENCODING, False)
        smtputf8 = config.get(SMTP_ALLOW_SMTPUTF8, False)

        if encoding:
            message_encoding = 'utf-8'
        else:
            message_encoding = 'ascii'

        # Validation for the 'from' email address
        if not email_from:
            return action_result.set_status(phantom.APP_ERROR, "Error: failed to get email sender")

        if not len(email_to):
            return action_result.set_status(phantom.APP_ERROR, "Error: failed to get email recipents")

        if email_headers:
            try:
                email_headers = json.loads(email_headers)
            except:
                return action_result.set_status(phantom.APP_ERROR, "Error: custom email headers field is not valid json")

            if not isinstance(email_headers, dict):
                return action_result.set_status(phantom.APP_ERROR, "Error: custom email headers field is not a dictionary")

        else:
            email_headers = {}

        if attachment_json:
            try:
                attachment_json = json.loads(attachment_json)
            except:
                return action_result.set_status(phantom.APP_ERROR, "Error: attachment json field is not valid json")

            if not isinstance(attachment_json, list):
                return action_result.set_status(phantom.APP_ERROR, "Error: attachment json field is not a list")

            has_dictionary = False
            for x in attachment_json:
                if isinstance(x, dict) and x.get('vault_id'):
                    has_dictionary = True
                    break

            if not has_dictionary:
                return action_result.set_status(phantom.APP_ERROR, "Error: attachment json field does not contain any dictionaries with the \"vault_id\" key")

            for attachment in attachment_json:
                for key, value in list(attachment.items()):
                    attachment.pop(key)
                    attachment[self._handle_py_ver_compat_for_input_str(key)] = self._handle_py_ver_compat_for_input_str(value)

        else:
            attachment_json = []

        for i in range(1, 6):
            attachment_json += [
                {
                    'vault_id': self._handle_py_ver_compat_for_input_str(param.get('attachment{}'.format(i))),
                    'content_id': self._handle_py_ver_compat_for_input_str(param.get('content_id{}'.format(i)))
                }
            ]

        attachment_json = list(filter(lambda x: isinstance(x, dict) and x.get('vault_id'), attachment_json))

        root = MIMEMultipart('related')

        root['from'] = email_from
        root['to'] = ",".join(email_to)

        if email_cc:
            root['cc'] = ", ".join(email_cc)
            email_to.extend(email_cc)

        if email_bcc:
            email_to.extend(email_bcc)

        if email_subject:
            root['subject'] = self._handle_py_ver_compat_for_input_str(email_subject)

        for k, v in list(email_headers.items()):
            k = self._handle_py_ver_compat_for_input_str(k)
            root[k] = self._handle_py_ver_compat_for_input_str(v)

        if not email_text:
            email_text = self.html_to_text(email_html)

        msg = MIMEMultipart('alternative')

        try:
            if message_encoding == 'utf-8':
                msg.attach(MIMEText(self._handle_py_ver_compat_for_input_str(email_text), 'plain', 'utf-8'))
                msg.attach(MIMEText(self._handle_py_ver_compat_for_input_str(email_html), 'html', 'utf-8'))
            else:
                msg.attach(MIMEText(email_text, 'plain', 'ascii'))
                msg.attach(MIMEText(email_html, 'html', 'ascii'))
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "{0} Error message: {1}".format(SMTP_UNICODE_ERROR_MSG, self._get_error_message_from_exception(e)))
        root.attach(msg)

        for x in attachment_json:
            vault_id = x['vault_id']
            content_id = x.get('content_id')
            try:
                _, _, data = ph_rules.vault_info(container_id=self.get_container_id(), vault_id=vault_id)
                if not data:
                    _, _, data = ph_rules.vault_info(vault_id=vault_id)
                data = list(data)
            except:
                return action_result.set_status(phantom.APP_ERROR, "Error: failed to find vault ID: {}".format(vault_id))

            if data and len(data) > 0 and isinstance(data[0], dict) and data[0].get('path'):
                path = data[0].get('path')

                attachment_path = data[0].get('name')
                filename = os.path.basename(attachment_path)
                filename = self._handle_py_ver_compat_for_input_str(filename)
                ctype, encoding = mimetypes.guess_type(attachment_path)
                if ctype is None:
                    ctype = 'application/octet-stream'
                maintype, subtype = ctype.split('/', 1)

                try:
                    if maintype == 'text':
                        with open(path, "r") as fp:
                            attachment = MIMEText(fp.read(), _subtype=subtype)

                    elif maintype == 'message':
                        with open(path, "r") as fp:
                            base_msg = message_from_file(fp)
                            attachment = MIMEMessage(base_msg, _subtype=subtype)

                    elif maintype == 'image':
                        # Python 2to3 change
                        with open(path, "rb") as fp:
                            attachment = MIMEImage(fp.read(), _subtype=subtype)

                    else:
                        with open(path, "rb") as rfp:
                            attachment = MIMEBase(maintype, subtype)
                            attachment.set_payload(rfp.read())
                            encoders.encode_base64(attachment)

                except:
                    return action_result.set_status(phantom.APP_ERROR, "Error: failed to read the file for the vault ID: {}".format(vault_id))

                attachment.add_header('Content-Disposition', 'attachment', filename=filename)
                if content_id:
                    attachment.add_header('Content-ID', "<{}>".format(content_id.strip().lstrip('<').rstrip('>').strip()))

                root.attach(attachment)

            else:
                return action_result.set_status(phantom.APP_ERROR, "Error: failed to find vault id: {}".format(vault_id))

        try:
            # Provided mail_options=["SMTPUTF8"], to allow Unicode characters for py3 in to_list parameter
            # This will ensure that the to_list gets encoded with 'utf-8' and not the default encoding which is 'ascii'
            mail_options = list()
            if smtputf8:
                mail_options.append("SMTPUTF8")
            self._smtp_conn.sendmail(email_from, email_to, root.as_string(), mail_options=mail_options)

        except UnicodeEncodeError:
            return action_result.set_status(phantom.APP_ERROR, "{} {}".format(SMTP_ERR_SMTP_SEND_EMAIL, SMTP_ERR_SMTPUTF8_CONFIG))
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "{} {}".format(SMTP_ERR_SMTP_SEND_EMAIL, self._get_error_message_from_exception(e)))

        return action_result.set_status(phantom.APP_SUCCESS, SMTP_SUCC_SMTP_EMAIL_SENT)

    def _handle_send_rawemail(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(param))

        config = self.get_config()
        smtputf8 = config.get(SMTP_ALLOW_SMTPUTF8, False)
        raw_email = self._handle_py_ver_compat_for_input_str(param['raw_email'])
        raw_email = raw_email.replace("\\n", "\n")
        msg = message_from_string(raw_email)
        email_from = msg.get('from', '')
        email_to_str = msg.get('to', '')
        # email_to = ",".join(filter(lambda x: x, [ msg['to'], msg['cc'], msg['bcc'] ]))
        # email_to = [y for x in email_to.split(',') for y in x.split() if y]
        # Filter method returns a Filter object on Python v3 and a List on Python v2
        # So, to maintain the uniformity the Filter object has been explicitly type casted to List

        if not len(email_from):
            return action_result.set_status(phantom.APP_ERROR, SMTP_ERR_TO_FROM_UNAVAILABLE.format("sender (from)"))

        # In case the user provides 'CC' or 'BCC' but does not provide 'To'
        if not len(email_to_str):
            return action_result.set_status(phantom.APP_ERROR, SMTP_ERR_TO_FROM_UNAVAILABLE.format("recipient (to)"))

        email_to = [x.strip() for x in msg['to'].split(",")]
        if msg['cc']:
            email_to.extend([x.strip() for x in msg['cc'].split(",")])
        if msg['bcc']:
            email_to.extend([x.strip() for x in msg['bcc'].split(",")])
            # Remove BCC field from the headers as we do not want to display it in the email's headers
            for header in msg._headers:
                if header[0].lower() == "bcc":
                    msg._headers.remove(header)

        email_to = list(filter(None, email_to))

        try:
            # Provided mail_options=["SMTPUTF8"], to allow Unicode characters for py3 in to_list parameter
            # This will ensure that the to_list gets encoded with 'utf-8' and not the default encoding which is 'ascii'
            mail_options = list()
            if smtputf8:
                mail_options.append("SMTPUTF8")
            self._smtp_conn.sendmail(email_from, email_to, msg.as_string(), mail_options=mail_options)

        except UnicodeEncodeError:
            return action_result.set_status(phantom.APP_ERROR, "{} {}".format(SMTP_ERR_SMTP_SEND_EMAIL, SMTP_ERR_SMTPUTF8_CONFIG))
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "{} {}".format(SMTP_ERR_SMTP_SEND_EMAIL, self._get_error_message_from_exception(e)))

        return action_result.set_status(phantom.APP_SUCCESS, SMTP_SUCC_SMTP_EMAIL_SENT)

    def handle_action(self, param):
        """Function that handles all the actions

            Args:

            Return:
                A status code
        """

        # Get the action that we are supposed to carry out, set it in the connection result object
        action = self.get_action_identifier()
        ret_val = phantom.APP_ERROR

        if (action == self.ACTION_ID_SEND_EMAIL):
            ret_val = self._handle_send_email(param)
        elif (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_asset_connectivity(param)

        elif action == "send_rawemail":
            ret_val = self._handle_send_rawemail(param)

        elif action == "send_htmlemail":
            ret_val = self._handle_send_htmlemail(param)

        return ret_val


if __name__ == '__main__':

    import argparse
    import requests

    # pudb.set_trace()

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
            login_url = SmtpConnector._get_phantom_base_url() + '/login'

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

        connector = SmtpConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
