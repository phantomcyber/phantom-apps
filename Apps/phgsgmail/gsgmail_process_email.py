# File: gsgmail_process_email.py
# Copyright (c) 2017-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

import email
import tempfile
from collections import OrderedDict
import os
import re
from bs4 import BeautifulSoup, UnicodeDammit
import phantom.app as phantom
import phantom.utils as ph_utils
import mimetypes
import socket
from email.header import decode_header, make_header
import shutil
import hashlib
import json
import magic
import random
import string
import phantom.rules as phantom_rules
from gsgmail_consts import *
import sys
from requests.structures import CaseInsensitiveDict

_container_common = {
    "run_automation": False  # Don't run any playbooks, when this artifact is added
}

_artifact_common = {
    "run_automation": False  # Don't run any playbooks, when this artifact is added
}

FILE_EXTENSIONS = {
  '.vmsn': ['os memory dump', 'vm snapshot file'],
  '.vmss': ['os memory dump', 'vm suspend file'],
  '.js': ['javascript'],
  '.doc': ['doc'],
  '.docx': ['doc'],
  '.xls': ['xls'],
  '.xlsx': ['xls'],
}

MAGIC_FORMATS = [
  (re.compile('^PE.* Windows'), ['pe file', 'hash']),
  (re.compile('^MS-DOS executable'), ['pe file', 'hash']),
  (re.compile('^PDF '), ['pdf']),
  (re.compile('^MDMP crash'), ['process dump']),
  (re.compile('^Macromedia Flash'), ['flash']),
]

EWS_DEFAULT_ARTIFACT_COUNT = 100
EWS_DEFAULT_CONTAINER_COUNT = 100
HASH_FIXED_PHANTOM_VERSION = "2.0.201"

OFFICE365_APP_ID = "a73f6d32-c9d5-4fec-b024-43876700daa6"
EXCHANGE_ONPREM_APP_ID = "badc5252-4a82-4a6d-bc53-d1e503857124"
IMAP_APP_ID = "9f2e9f72-b0e5-45d6-92a7-09ef820476c1"

uri_regexc = re.compile(URI_REGEX)
email_regexc = re.compile(EMAIL_REGEX, re.IGNORECASE)
email_regexc2 = re.compile(EMAIL_REGEX2, re.IGNORECASE)
hash_regexc = re.compile(HASH_REGEX)
ip_regexc = re.compile(IP_REGEX)
ipv6_regexc = re.compile(IPV6_REGEX)


class ProcessMail:

    def __init__(self, base_connector, config):
        self._base_connector = base_connector
        self._config = config
        self._email_id_contains = list()
        self._container = dict()
        self._artifacts = list()
        self._attachments = list()
        self._python_version = None

        try:
            self._python_version = int(sys.version_info[0])
        except Exception:
            raise Exception("Error occurred while getting the Phantom server's Python major version.")

    def _get_file_contains(self, file_path):

        contains = []
        ext = os.path.splitext(file_path)[1]
        contains.extend(FILE_EXTENSIONS.get(ext, []))
        magic_str = magic.from_file(file_path)
        for regex, cur_contains in MAGIC_FORMATS:
            if regex.match(magic_str):
                contains.extend(cur_contains)

        return contains

    def _is_ip(self, input_ip):

        if ph_utils.is_ip(input_ip):
            return True

        if self.is_ipv6(input_ip):
            return True

        return False

    def is_ipv6(self, input_ip):

        try:
            socket.inet_pton(socket.AF_INET6, input_ip)
        except Exception:
            return False

        return True

    def _clean_url(self, url):

        url = url.strip('>),.]\r\n')

        # Check before splicing, find returns -1 if not found
        # _and_ you will end up splicing on -1 (incorrectly)
        if '<' in url:
            url = url[:url.find('<')]
        elif '>' in url:
            url = url[:url.find('>')]

        return url

    def _extract_urls_domains(self, file_data, urls, domains):

        if not self._config[PROC_EMAIL_JSON_EXTRACT_DOMAINS] and not self._config[PROC_EMAIL_JSON_EXTRACT_URLS]:
            return

        # try to load the email
        try:
            soup = BeautifulSoup(file_data, "html.parser")
        except Exception as e:
            self._base_connector.debug_print(e)
            return

        uris = []
        # get all tags that have hrefs
        links = soup.find_all(href=True)
        if links:
            # it's html, so get all the urls
            uris = [x['href'] for x in links if (not x['href'].startswith('mailto:'))]
            # work on the text part of the link, they might be http links different from the href
            # and were either missed by the uri_regexc while parsing text or there was no text counterpart
            # in the email
            uri_text = [self._clean_url(x.get_text()) for x in links]
            if uri_text:
                uri_text = [x for x in uri_text if x.startswith('http')]
                if uri_text:
                    uris.extend(uri_text)
        else:
            # Parse it as a text file
            uris = re.findall(uri_regexc, file_data)
            if uris:
                uris = [self._clean_url(x) for x in uris]

        if self._config[PROC_EMAIL_JSON_EXTRACT_URLS]:
            # add the uris to the urls
            urls |= set(uris)

        if self._config[PROC_EMAIL_JSON_EXTRACT_DOMAINS]:
            for uri in uris:
                domain = phantom.get_host_from_url(uri)
                if domain and not self._is_ip(domain):
                    domains.add(domain)
            # work on any mailto urls if present
            if links:
                mailtos = [x['href'] for x in links if (x['href'].startswith('mailto:'))]
                for curr_email in mailtos:
                    domain = curr_email[curr_email.find('@') + 1:]
                    if domain and not self._is_ip(domain):
                        domains.add(domain)

        return

    def _get_ips(self, file_data, ips):

        # First extract what looks like an IP from the file, this is a faster operation
        ips_in_mail = re.findall(ip_regexc, file_data)
        ip6_in_mail = re.findall(ipv6_regexc, file_data)

        if ip6_in_mail:
            for ip6_tuple in ip6_in_mail:
                ip6s = [x for x in ip6_tuple if x]
                ips_in_mail.extend(ip6s)

        # Now validate them
        if ips_in_mail:
            ips_in_mail = set(ips_in_mail)
            ips_in_mail = [x for x in ips_in_mail if self._is_ip(x)]
            if ips_in_mail:
                ips |= set(ips_in_mail)

    def _handle_body(self, body, parsed_mail, email_id):

        local_file_path = body['file_path']
        ips = parsed_mail[PROC_EMAIL_JSON_IPS]
        hashes = parsed_mail[PROC_EMAIL_JSON_HASHES]
        urls = parsed_mail[PROC_EMAIL_JSON_URLS]
        domains = parsed_mail[PROC_EMAIL_JSON_DOMAINS]

        file_data = None

        try:
            with open(local_file_path, 'r') as f:
                file_data = f.read()
        except Exception:
            with open(local_file_path, 'rb') as f:
                file_data = f.read()
            self._base_connector.debug_print("Reading file data using binary mode")

        if (file_data is None) or (len(file_data) == 0):
            return phantom.APP_ERROR

        file_data = UnicodeDammit(file_data).unicode_markup.encode('utf-8').decode('utf-8')

        self._parse_email_headers_as_inline(file_data, parsed_mail, email_id)

        if self._config[PROC_EMAIL_JSON_EXTRACT_DOMAINS]:
            emails = []
            emails.extend(re.findall(email_regexc, file_data))
            emails.extend(re.findall(email_regexc2, file_data))

            for curr_email in emails:
                domain = curr_email[curr_email.rfind('@') + 1:]
                if domain and (not ph_utils.is_ip(domain)):
                    domains.add(domain)

        self._extract_urls_domains(file_data, urls, domains)

        if self._config[PROC_EMAIL_JSON_EXTRACT_IPS]:
            self._get_ips(file_data, ips)

        if self._config[PROC_EMAIL_JSON_EXTRACT_HASHES]:
            hashs_in_mail = re.findall(hash_regexc, file_data)
            if hashs_in_mail:
                hashes |= set(hashs_in_mail)

        return phantom.APP_SUCCESS

    def _add_artifacts(self, cef_key, input_set, artifact_name, start_index, artifacts):

        added_artifacts = 0
        for entry in input_set:

            # ignore empty entries
            if not entry:
                continue

            artifact = {}
            artifact.update(_artifact_common)
            artifact['source_data_identifier'] = start_index + added_artifacts
            artifact['cef'] = {cef_key: entry}
            artifact['name'] = artifact_name
            self._base_connector.debug_print('Artifact:', artifact)
            artifacts.append(artifact)
            added_artifacts += 1

        return added_artifacts

    def _parse_email_headers_as_inline(self, file_data, parsed_mail, email_id):

        # remove the 'Forwarded Message' from the email text and parse it
        p = re.compile(r'(?<=\r\n).*Forwarded Message.*\r\n', re.IGNORECASE)
        email_text = p.sub('', file_data.strip())
        mail = email.message_from_string(email_text)
        self._parse_email_headers(parsed_mail, mail, add_email_id=email_id)

        return phantom.APP_SUCCESS

    def _add_email_header_artifacts(self, email_header_artifacts, start_index, artifacts):

        added_artifacts = 0
        for artifact in email_header_artifacts:
            artifact['source_data_identifier'] = start_index + added_artifacts
            artifacts.append(artifact)
            added_artifacts += 1

        return added_artifacts

    def _create_artifacts(self, parsed_mail):

        # get all the artifact data in their own list objects
        ips = parsed_mail[PROC_EMAIL_JSON_IPS]
        hashes = parsed_mail[PROC_EMAIL_JSON_HASHES]
        urls = parsed_mail[PROC_EMAIL_JSON_URLS]
        domains = parsed_mail[PROC_EMAIL_JSON_DOMAINS]
        email_headers = parsed_mail[PROC_EMAIL_JSON_EMAIL_HEADERS]

        # set the default artifact dict

        artifact_id = 0

        # add artifacts
        added_artifacts = self._add_artifacts('sourceAddress', ips, 'IP Artifact', artifact_id, self._artifacts)
        artifact_id += added_artifacts

        added_artifacts = self._add_artifacts('fileHash', hashes, 'Hash Artifact', artifact_id, self._artifacts)
        artifact_id += added_artifacts

        added_artifacts = self._add_artifacts('requestURL', urls, 'URL Artifact', artifact_id, self._artifacts)
        artifact_id += added_artifacts

        added_artifacts = self._add_artifacts('destinationDnsDomain', domains, 'Domain Artifact', artifact_id, self._artifacts)
        artifact_id += added_artifacts

        added_artifacts = self._add_email_header_artifacts(email_headers, artifact_id, self._artifacts)
        artifact_id += added_artifacts

        return phantom.APP_SUCCESS

    def _decode_uni_string(self, input_str, def_name):

        # try to find all the decoded strings, we could have multiple decoded strings
        # or a single decoded string between two normal strings separated by \r\n
        # YEAH...it could get that messy
        encoded_strings = re.findall(r'=\?.*?\?=', input_str, re.I)

        # return input_str as is, no need to do any conversion
        if not encoded_strings:
            return input_str

        # get the decoded strings
        try:
            decoded_strings = [decode_header(x)[0] for x in encoded_strings]
            decoded_strings = [{'value': x[0], 'encoding': x[1]} for x in decoded_strings]
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            self._base_connector.debug_print("Decoding: {0}. Error code: {1}. Error message: {2}".format(encoded_strings, error_code, error_msg))
            return def_name

        # convert to dict for safe access, if it's an empty list, the dict will be empty
        decoded_strings = dict(enumerate(decoded_strings))

        new_str = ''
        new_str_create_count = 0
        for i, encoded_string in enumerate(encoded_strings):

            decoded_string = decoded_strings.get(i)

            if not decoded_string:
                # nothing to replace with
                continue

            value = decoded_string.get('value')
            encoding = decoded_string.get('encoding')

            if not encoding or not value:
                # nothing to replace with
                continue

            try:
                if encoding != 'utf-8':
                    value = str(value, encoding)
            except Exception:
                pass

            try:
                # commenting the existing approach due to a new approach being deployed below
                # substitute the encoded string with the decoded one
                # input_str = input_str.replace(encoded_string, value)
                # make new string insted of replacing in the input string because issue find in PAPP-9531
                if value:
                    new_str += UnicodeDammit(value).unicode_markup
                    new_str_create_count += 1
            except Exception:
                pass
        # replace input string with new string because issue find in PAPP-9531
        if new_str and new_str_create_count == len(encoded_strings):
            self._base_connector.debug_print("Creating a new string entirely from the encoded_strings and assiging into input_str")
            input_str = new_str

        return input_str

    def _get_container_name(self, parsed_mail, email_id):

        # Create the default name
        def_cont_name = "Email ID: {0}".format(email_id)

        # get the subject from the parsed mail
        subject = parsed_mail.get(PROC_EMAIL_JSON_SUBJECT)

        # if no subject then return the default
        if not subject:
            return def_cont_name

        try:
            return str(make_header(decode_header(subject)))
        except Exception:
            return self._decode_uni_string(subject, def_cont_name)

    def _handle_if_body(self, content_disp, content_type, part, bodies, file_path, parsed_mail):

        process_as_body = False

        # if content disposition is None then assume that it is
        if content_disp is None:
            process_as_body = True
        # if content disposition is inline
        elif content_disp.lower().strip() == 'inline':
            if ('text/html' in content_type) or ('text/plain' in content_type):
                process_as_body = True

        if not process_as_body:
            return phantom.APP_SUCCESS, True

        part_payload = part.get_payload(decode=True)

        if not part_payload:
            return phantom.APP_SUCCESS, False

        charset = part.get_content_charset()

        with open(file_path, 'wb') as f:  # noqa
            f.write(part_payload)

        bodies.append({'file_path': file_path, 'charset': part.get_content_charset()})

        self._add_body_in_email_headers(parsed_mail, file_path, charset, content_type)
        return phantom.APP_SUCCESS, False

    def _handle_part(self, part, part_index, tmp_dir, extract_attach, parsed_mail):

        bodies = parsed_mail[PROC_EMAIL_JSON_BODIES]
        files = parsed_mail[PROC_EMAIL_JSON_FILES]

        # get the file_name
        file_name = part.get_filename()
        content_disp = part.get('Content-Disposition')
        content_type = part.get('Content-Type')
        content_id = part.get('Content-ID')

        if file_name is None:
            # init name and extension to default values
            name = "part_{0}".format(part_index)
            extension = ".{0}".format(part_index)

            # Try to create an extension from the content type if possible
            if content_type is not None:
                extension = mimetypes.guess_extension(re.sub(';.*', '', content_type))

            # Try to create a name from the content id if possible
            if content_id is not None:
                name = content_id

            file_name = "{0}{1}".format(name, extension)
        else:
            try:
                file_name = str(make_header(decode_header(file_name)))
            except Exception:
                file_name = self._decode_uni_string(file_name, file_name)
        # Remove any chars that we don't want in the name
        file_path = "{0}/{1}_{2}".format(tmp_dir, part_index,
                                         file_name.translate(str.maketrans("", "", ''.join(['<', '>', ' ']))))

        self._base_connector.debug_print("file_path: {0}".format(file_path))

        # is the part representing the body of the email
        status, process_further = self._handle_if_body(content_disp, content_type, part, bodies, file_path, parsed_mail)

        if not process_further:
            return phantom.APP_SUCCESS

        # is this another email as an attachment
        if (content_type is not None) and (content_type.find(PROC_EMAIL_CONTENT_TYPE_MESSAGE) != -1):
            return phantom.APP_SUCCESS

        # This is an attachment, first check if it is another email or not
        if extract_attach:
            _, file_extension = os.path.splitext(file_name)
            part_payload = part.get_payload(decode=True)
            if not part_payload:
                return phantom.APP_SUCCESS
            try:
                with open(file_path, 'wb') as f:  # noqa
                    f.write(part_payload)
                files.append({'file_name': file_name, 'file_path': file_path})
            except IOError as e:
                error_msg = self._get_error_message_from_exception(e)
                if "File name too long" in error_msg:
                    self.write_with_new_filename(tmp_dir, part_payload, file_extension, files, file_name, as_byte=False)
                else:
                    self._base_connector.debug_print('Failed to write file: {}'.format(e))

        return phantom.APP_SUCCESS

    def _get_file_name(self, input_str):
        try:
            return str(make_header(decode_header(input_str)))
        except Exception:
            return self._decode_uni_string(input_str, input_str)

    def _parse_email_headers(self, parsed_mail, part, charset=None, add_email_id=None):

        email_header_artifacts = parsed_mail[PROC_EMAIL_JSON_EMAIL_HEADERS]
        email_headers = part.items()
        if not email_headers:
            return 0

        # Parse email keys first

        headers = self._get_email_headers_from_part(part, charset)

        cef_artifact = {}
        cef_types = {}

        if headers.get('From'):
            emails = headers['From']
            if emails:
                cef_artifact.update({'fromEmail': emails})

        if headers.get('To'):
            emails = headers['To']
            if emails:
                cef_artifact.update({'toEmail': emails})

        message_id = headers.get('Message-ID')
        # if the header did not contain any email addresses and message ID then ignore this artifact
        if not cef_artifact and not message_id:
            return 0

        cef_types.update({'fromEmail': ['email'], 'toEmail': ['email']})

        if headers:
            cef_artifact['emailHeaders'] = headers

        # Adding the email id as a cef artifact crashes the UI when trying to show the action dialog box
        # so not adding this right now. All the other code to process the emailId is there, but the refraining
        # from adding the emailId
        # add_email_id = False
        if add_email_id:
            cef_artifact['emailId'] = add_email_id
            if self._email_id_contains:
                cef_types.update({'emailId': self._email_id_contains})

        artifact = {}
        artifact.update(_artifact_common)
        artifact['name'] = 'Email Artifact'
        artifact['cef'] = cef_artifact
        artifact['cef_types'] = cef_types
        email_header_artifacts.append(artifact)

        return len(email_header_artifacts)

    def _get_email_headers_from_part(self, part, charset=None):

        email_headers = list(part.items())

        # TODO: the next 2 ifs can be condensed to use 'or'
        if charset is None:
            charset = part.get_content_charset()

        if charset is None:
            charset = 'utf8'

        if not email_headers:
            return {}
        # Convert the header tuple into a dictionary
        headers = CaseInsensitiveDict()
        try:
            [headers.update({x[0]: self._get_string(x[1], charset)}) for x in email_headers]
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            err = "Error occurred while converting the header tuple into a dictionary"
            self._base_connector.debug_print("{}. {}. {}".format(err, error_code, error_msg))

        # Handle received separately
        try:
            received_headers = [self._get_string(x[1], charset) for x in email_headers if x[0].lower() == 'received']
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            err = "Error occurred while handling the received header tuple separately"
            self._base_connector.debug_print("{}. {}. {}".format(err, error_code, error_msg))

        if received_headers:
            headers['Received'] = received_headers

        # handle the subject string, if required add a new key
        subject = headers.get('Subject')

        if subject:
            try:
                headers['decodedSubject'] = str(make_header(decode_header(subject)))
            except Exception:
                headers['decodedSubject'] = self._decode_uni_string(subject, subject)
        return dict(headers)

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
                    error_code = "Error code unavailable"
                    error_msg = e.args[0]
            else:
                error_code = "Error code unavailable"
                error_msg = "Error message unavailable. Please check the asset configuration and|or action parameters."
        except Exception:
            error_code = "Error code unavailable"
            error_msg = "Error message unavailable. Please check the asset configuration and|or action parameters."

        return error_code, error_msg

    def _handle_mail_object(self, mail, email_id, rfc822_email, tmp_dir, start_time_epoch):

        parsed_mail = OrderedDict()

        # Create a tmp directory for this email, will extract all files here
        tmp_dir = tmp_dir
        if not os.path.exists(tmp_dir):
            os.makedirs(tmp_dir)

        extract_attach = self._config[PROC_EMAIL_JSON_EXTRACT_ATTACHMENTS]

        charset = mail.get_content_charset()

        if charset is None:
            charset = 'utf-8'

        # Extract fields and place it in a dictionary
        parsed_mail[PROC_EMAIL_JSON_SUBJECT] = mail.get('Subject', '')
        parsed_mail[PROC_EMAIL_JSON_FROM] = mail.get('From', '')
        parsed_mail[PROC_EMAIL_JSON_TO] = mail.get('To', '')
        parsed_mail[PROC_EMAIL_JSON_DATE] = mail.get('Date', '')
        parsed_mail[PROC_EMAIL_JSON_MSG_ID] = mail.get('Message-ID', '')
        parsed_mail[PROC_EMAIL_JSON_FILES] = files = []
        parsed_mail[PROC_EMAIL_JSON_BODIES] = bodies = []
        parsed_mail[PROC_EMAIL_JSON_START_TIME] = start_time_epoch
        parsed_mail[PROC_EMAIL_JSON_EMAIL_HEADERS] = []

        # parse the parts of the email
        if mail.is_multipart():
            for i, part in enumerate(mail.walk()):
                add_email_id = None
                if i == 0:
                    add_email_id = email_id

                self._parse_email_headers(parsed_mail, part, add_email_id=add_email_id)

                self._base_connector.debug_print("part: {0}".format(part.__dict__))
                self._base_connector.debug_print("part type", type(part))
                if part.is_multipart():
                    self.check_and_update_eml(part)
                    continue
                try:
                    ret_val = self._handle_part(part, i, tmp_dir, extract_attach, parsed_mail)
                except Exception as e:
                    self._base_connector.debug_print("ErrorExp in _handle_part # {0}".format(i), e)
                    continue

                if phantom.is_fail(ret_val):
                    continue

        else:
            self._parse_email_headers(parsed_mail, mail, add_email_id=email_id)
            # parsed_mail[PROC_EMAIL_JSON_EMAIL_HEADERS].append(mail.items())
            file_path = "{0}/part_1.text".format(tmp_dir)
            with open(file_path, 'wb') as f:  # noqa
                f.write(mail.get_payload(decode=True))
            bodies.append({'file_path': file_path, 'charset': charset})
            self._add_body_in_email_headers(parsed_mail, file_path, mail.get_content_charset(), 'text/plain')

        # get the container name
        container_name = self._get_container_name(parsed_mail, email_id)

        if container_name is None:
            return phantom.APP_ERROR

        # Add the container
        # first save the container, to do that copy things from parsed_mail to a new object
        container = {}
        container_data = dict(parsed_mail)

        # delete the header info, we dont make it a part of the container json
        del (container_data[PROC_EMAIL_JSON_EMAIL_HEADERS])
        container.update(_container_common)
        self._container['source_data_identifier'] = email_id
        self._container['name'] = container_name
        self._container['data'] = {'raw_email': rfc822_email}

        # Create the sets before handling the bodies If both the bodies add the same ip
        # only one artifact should be created
        parsed_mail[PROC_EMAIL_JSON_IPS] = set()
        parsed_mail[PROC_EMAIL_JSON_HASHES] = set()
        parsed_mail[PROC_EMAIL_JSON_URLS] = set()
        parsed_mail[PROC_EMAIL_JSON_DOMAINS] = set()

        # For bodies
        for i, body in enumerate(bodies):
            if not body:
                continue

            try:
                self._handle_body(body, parsed_mail, email_id)
            except Exception as e:
                self._base_connector.debug_print_debug_print("ErrorExp in _handle_body # {0}: {1}".format(i, str(e)))
                continue

        # Files
        self._attachments.extend(files)

        self._create_artifacts(parsed_mail)

        return phantom.APP_SUCCESS

    def _add_body_in_email_headers(self, parsed_mail, file_path, charset, content_type):

        # Add email_bodies to email_headers
        email_headers = parsed_mail[PROC_EMAIL_JSON_EMAIL_HEADERS]

        try:
            with open(file_path, 'r') as f:
                body_content = f.read()
        except Exception:
            with open(file_path, 'rb') as f:
                body_content = f.read()
            self._base_connector.debug_print("Reading file data using binary mode")
        # Add body to the last added Email artifact
        body_content = UnicodeDammit(body_content).unicode_markup.encode('utf-8').decode('utf-8')
        if 'text/plain' in content_type:
            try:
                email_headers[-1]['cef']['bodyText'] = self._get_string(
                    body_content, charset)
            except Exception as e:
                try:
                    email_headers[-1]['cef']['bodyText'] = str(make_header(decode_header(body_content)))
                except Exception:
                    email_headers[-1]['cef']['bodyText'] = self._decode_uni_string(body_content, body_content)
                error_code, error_msg = self._get_error_message_from_exception(e)
                err = "Error occurred while parsing text/plain body content for creating artifacts"
                self._base_connector.debug_print("{}. {}. {}".format(err, error_code, error_msg))

        elif 'text/html' in content_type:
            try:
                email_headers[-1]['cef']['bodyHtml'] = self._get_string(
                    body_content, charset)
            except Exception as e:
                try:
                    email_headers[-1]['cef']['bodyHtml'] = str(make_header(decode_header(body_content)))
                except Exception:
                    email_headers[-1]['cef']['bodyHtml'] = self._decode_uni_string(body_content, body_content)
                error_code, error_msg = self._get_error_message_from_exception(e)
                err = "Error occurred while parsing text/html body content for creating artifacts"
                self._base_connector.debug_print("{}. {}. {}".format(err, error_code, error_msg))

        else:
            if not email_headers[-1]['cef'].get('bodyOther'):
                email_headers[-1]['cef']['bodyOther'] = {}
            try:
                email_headers[-1]['cef']['bodyOther'][content_type] = self._get_string(
                    body_content, charset)
            except Exception as e:
                try:
                    email_headers[-1]['cef']['bodyOther'][content_type] = str(make_header(decode_header(body_content)))
                except Exception:
                    email_headers[-1]['cef']['bodyOther'][content_type] = self._decode_uni_string(body_content, body_content)
                error_code, error_msg = self._get_error_message_from_exception(e)
                err = "Error occurred while parsing bodyOther content for creating artifacts"
                self._base_connector.debug_print("{}. {}. {}".format(err, error_code, error_msg))

    def _get_string(self, input_str, charset):

        try:
            if input_str:
                if self._python_version == 2:
                    input_str = UnicodeDammit(input_str).unicode_markup.encode(charset)
                else:
                    input_str = UnicodeDammit(input_str).unicode_markup.encode(charset).decode(charset)
        except Exception:
            try:
                input_str = str(make_header(decode_header(input_str)))
            except Exception:
                input_str = self._decode_uni_string(input_str, input_str)
            self._base_connector.debug_print(
                "Error occurred while converting to string with specific encoding {}".format(input_str))

        return input_str

    def _set_email_id_contains(self, email_id):

        if not self._base_connector:
            return

        try:
            email_id = self._get_string(email_id, 'utf-8')
        except Exception:
            email_id = str(email_id)

        if self._base_connector.get_app_id() == EXCHANGE_ONPREM_APP_ID and email_id.endswith('='):
            self._email_id_contains = ["exchange email id"]
        elif self._base_connector.get_app_id() == OFFICE365_APP_ID and email_id.endswith('='):
            self._email_id_contains = ["office 365 email id"]
        elif self._base_connector.get_app_id() == IMAP_APP_ID and email_id.isdigit():
            self._email_id_contains = ["imap email id"]
        elif ph_utils.is_sha1(email_id):
            self._email_id_contains = ["vault id"]

        return

    def _int_process_email(self, rfc822_email, email_id, start_time_epoch):
        mail = email.message_from_string(rfc822_email)
        tmp_dir = tempfile.mkdtemp(prefix='ph_email')
        try:
            ret_val = self._handle_mail_object(mail, email_id, rfc822_email, tmp_dir, start_time_epoch)
        except Exception as e:
            message = "ErrorExp in _handle_mail_object: {0}".format(e)
            self._base_connector.debug_print(message)
            return phantom.APP_ERROR, message, []

        results = [{'container': self._container, 'artifacts': self._artifacts, 'files': self._attachments, 'temp_directory': tmp_dir}]

        return ret_val, PROC_EMAIL_PARSED, results

    def check_and_update_eml(self, part):
        if self._config[PROC_EMAIL_JSON_EXTRACT_EMAIL_ATTACHMENTS]:
            msg = None
            tmp_dir = tempfile.mkdtemp(prefix='ph_email')
            filename = ''
            file_extension = ''
            try:
                filename = self._get_file_name(part.get_filename())
                _, file_extension = os.path.splitext(filename)
                if filename.endswith('.eml'):
                    file_path = os.path.join(tmp_dir, filename)
                    msg = part.get_payload()[0]
                    with open(file_path, 'wb') as f:  # noqa
                        f.write(msg.as_bytes())
                    self._attachments.append({'file_name': filename, 'file_path': file_path})
            except IOError as e:
                error_msg = self._get_error_message_from_exception(e)
                if "File name too long" in error_msg:
                    self.write_with_new_filename(tmp_dir, msg, file_extension, self._attachments, filename, as_byte=True)
                else:
                    self._base_connector.debug_print('Failed to write file: {}'.format(e))
            except Exception as e:
                self._base_connector.debug_print("Exception occurred: {}".format(e))

    def write_with_new_filename(self, tmp_dir, data, file_extension, dict_to_fill, file_name, as_byte=False):
        try:
            random_suffix = '_' + ''.join(random.SystemRandom().choice(string.ascii_lowercase) for _ in range(16))
            new_file_name = "ph_long_file_name_{0}{1}".format(random_suffix, file_extension)
            file_path = os.path.join(tmp_dir, new_file_name)
            with open(file_path, 'wb') as f:
                if as_byte:
                    f.write(data.as_bytes())
                else:
                    f.write(data)
            dict_to_fill.append({'file_name': file_name, 'file_path': file_path})
        except Exception as e:
            self._base_connector.debug_print('Exception while writing file: {}'.format(e))

    def process_email(self, rfc822_email, email_id, epoch):
        try:
            self._set_email_id_contains(email_id)
        except Exception:
            pass

        ret_val, message, results = self._int_process_email(rfc822_email, email_id, epoch)

        if not ret_val:
            return phantom.APP_ERROR, message

        self._parse_results(results)

        return phantom.APP_SUCCESS, PROC_EMAIL_PROCESSED

    def _parse_results(self, results):

        param = self._base_connector.get_current_param()

        container_count = EWS_DEFAULT_CONTAINER_COUNT
        artifact_count = EWS_DEFAULT_ARTIFACT_COUNT

        if param:
            container_count = param.get(phantom.APP_JSON_CONTAINER_COUNT, EWS_DEFAULT_CONTAINER_COUNT)
            artifact_count = param.get(phantom.APP_JSON_ARTIFACT_COUNT, EWS_DEFAULT_ARTIFACT_COUNT)

        results = results[:container_count]

        for result in results:
            container = result.get('container')

            if not container:
                continue

            container.update(_container_common)
            try:
                ret_val, message, container_id = self._base_connector.save_container(container)
            except Exception as e:
                self._base_connector.debug_print("Exception: ", e)
                continue

            self._base_connector.debug_print(PROC_EMAIL_SAVE_CONTAINER.format(ret_val, message, container_id))

            if phantom.is_fail(ret_val):
                message = PROC_EMAIL_FAILED_CONTAINER.format(container['source_data_identifier'], message)
                self._base_connector.debug_print(message)
                continue

            if not container_id:
                message = PROC_EMAIL_SAVE_CONTAINER_FAILED
                self._base_connector.debug_print(message)
                continue

            files = result.get('files')
            vault_artifacts_added = 0
            for curr_file in files:
                ret_val, added_to_vault = self._handle_file(curr_file, container_id)

                if added_to_vault:
                    vault_artifacts_added += 1

            artifacts = result.get('artifacts')
            if not artifacts:
                continue

            if not self._base_connector.is_poll_now():
                artifacts = artifacts[:artifact_count]

            len_artifacts = len(artifacts)
            for j, artifact in enumerate(artifacts):

                if not artifact:
                    continue

                # add the container id to the artifact
                artifact['container_id'] = container_id
                self._set_sdi(artifact)

                # if it is the last artifact of the last container
                if (j + 1) == len_artifacts:
                    # mark it such that active playbooks get executed
                    artifact['run_automation'] = True

                ret_val, artifact_message, artifact_id = self._base_connector.save_artifact(artifact)
                self._base_connector.debug_print(PROC_EMAIL_SAVE_CONT_PASSED.format(ret_val, artifact_message, artifact_id))

            if "Duplicate container found" in message and not self._base_connector.is_poll_now():
                self._base_connector._dup_emails += 1

        # delete any temp directories that were created by the email parsing function
        [shutil.rmtree(x['temp_directory'], ignore_errors=True) for x in results if x.get('temp_directory')]

        return self._base_connector.set_status(phantom.APP_SUCCESS)

    def _add_vault_hashes_to_dictionary(self, cef_artifact, vault_id):

        success, message, vault_info = phantom_rules.vault_info(vault_id=vault_id)

        if not vault_info:
            return phantom.APP_ERROR, "Vault ID not found"

        # The return value is a list, each item represents an item in the vault
        # matching the vault id, the info that we are looking for (the hashes)
        # will be the same for every entry, so just access the first one
        try:
            metadata = vault_info[0].get('metadata')
        except Exception:
            return phantom.APP_ERROR, PROC_EMAIL_FAILED_VAULT_CONT_DATA

        try:
            cef_artifact['fileHashSha256'] = metadata['sha256']
        except Exception:
            pass

        try:
            cef_artifact['fileHashMd5'] = metadata['md5']
        except Exception:
            pass

        try:
            cef_artifact['fileHashSha1'] = metadata['sha1']
        except Exception:
            pass

        return phantom.APP_SUCCESS, PROC_EMAIL_MAPPED_HASH_VAL

    def _handle_file(self, curr_file, container_id):

        file_name = curr_file.get('file_name')

        local_file_path = curr_file['file_path']

        contains = self._get_file_contains(local_file_path)

        # lets move the data into the vault
        vault_attach_dict = {}

        if not file_name:
            file_name = os.path.basename(local_file_path)

        self._base_connector.debug_print("Vault file name: {0}".format(file_name))

        vault_attach_dict[phantom.APP_JSON_ACTION_NAME] = self._base_connector.get_action_name()
        vault_attach_dict[phantom.APP_JSON_APP_RUN_ID] = self._base_connector.get_app_run_id()

        file_name = self._decode_uni_string(file_name, file_name)

        # success, message, vault_id = phantom_rules.vault_add(container_id, local_file_path, file_name)
        try:
            success, message, vault_id = phantom_rules.vault_add(file_location=local_file_path, container=container_id, file_name=file_name, metadata=vault_attach_dict)
        except Exception as e:
            self._base_connector.debug_print(phantom.APP_ERR_FILE_ADD_TO_VAULT.format(e))
            return phantom.APP_ERROR, phantom.APP_ERROR

        if not success:
            self._base_connector.debug_print(PROC_EMAIL_FAILED_VAULT_ADD_FILE.format(message))
            return phantom.APP_ERROR, phantom.APP_ERROR

        # add the vault id artifact to the container
        cef_artifact = {}
        if file_name:
            cef_artifact.update({'fileName': file_name})

        if vault_id:
            cef_artifact.update({'vaultId': vault_id,
                                 'cs6': vault_id,
                                 'cs6Label': 'Vault ID'})

            # now get the rest of the hashes and add them to the cef artifact
            self._add_vault_hashes_to_dictionary(cef_artifact, vault_id)

        if not cef_artifact:
            return phantom.APP_SUCCESS, phantom.APP_ERROR

        artifact = {}
        artifact.update(_artifact_common)
        artifact['container_id'] = container_id
        artifact['name'] = 'Vault Artifact'
        artifact['cef'] = cef_artifact
        if contains:
            artifact['cef_types'] = {'vaultId': contains, 'cs6': contains}
        self._set_sdi(artifact)

        ret_val, status_string, artifact_id = self._base_connector.save_artifact(artifact)
        self._base_connector.debug_print(PROC_EMAIL_SAVE_CONT_PASSED.format(ret_val, status_string, artifact_id))

        return phantom.APP_SUCCESS, ret_val

    def cmp2(self, a, b):
        return (a > b) - (a < b)

    def _set_sdi(self, input_dict):

        if 'source_data_identifier' in input_dict:
            del input_dict['source_data_identifier']
        dict_hash = None

        # first get the phantom version
        phantom_version = self._base_connector.get_product_version()

        if not phantom_version:
            dict_hash = self._create_dict_hash(input_dict)
        else:
            ver_cmp = self.cmp2(phantom_version, HASH_FIXED_PHANTOM_VERSION)
            if ver_cmp == -1:
                dict_hash = self._create_dict_hash(input_dict)

        if dict_hash:
            input_dict['source_data_identifier'] = dict_hash
        else:
            # Remove this code once the backend has fixed PS-4216 _and_ it has been
            # merged into next so that 2.0 and 2.1 has the code
            input_dict['source_data_identifier'] = self._create_dict_hash(input_dict)

        return phantom.APP_SUCCESS

    def _create_dict_hash(self, input_dict):

        try:
            input_dict_str = json.dumps(input_dict, sort_keys=True)
        except Exception as e:
            self._base_connector.debug_print('Exception: ', e)
            return None

        return hashlib.md5(input_dict_str.encode('utf-8')).hexdigest()
