#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Simple client for Resilient REST API"""
from __future__ import print_function

import json
import ssl
import mimetypes
import os
import sys
import logging
import datetime
import unicodedata
import requests
import importlib
from .patch import PatchStatus
from argparse import Namespace
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
from requests_toolbelt.multipart.encoder import MultipartEncoder
from cachetools import cachedmethod
from cachetools.ttl import TTLCache
try:
    # Python 3
    import urllib.parse as urlparse
except:
    # Python 2
    import urlparse

LOG = logging.getLogger(__name__)


def get_config_file(filename="app.config"):
    """
    Helper: get the location of the configuration file
    * Use the location specified in $APP_CONFIG_FILE, if set
    * Otherwise use path in the current working directory, if exists
    * Otherwise use path in ~/.resilient/ directory

    :param filename: the filename, defaults to 'app.config'
    """
    # The config file location should usually be set in the environment
    # First check environment, then cwd, then ~/.resilient/app.config
    env_app_config_file = os.environ.get("APP_CONFIG_FILE", None)
    if not env_app_config_file:
        if os.path.exists(filename):
            config_file = filename
        else:
            config_file = os.path.expanduser(os.path.join("~", ".resilient", filename))
    else:
        config_file = env_app_config_file
    return config_file


def get_client(opts):
    """
    Helper: get a SimpleClient for Resilient REST API.

    :param opts: the connection options, as a :class:`dict`, or a :class:`Namespace`

    Returns: a connected and verified instance of SimpleClient.
    """
    if isinstance(opts, Namespace):
        opts = vars(opts)

    # Allow explicit setting "do not verify certificates"
    verify = opts.get("cafile")
    if str(verify).lower() == "false":
        LOG.warn("Unverified HTTPS requests (cafile=false).")
        requests.packages.urllib3.disable_warnings()  # otherwise things get very noisy
        verify = False

    proxy = None
    if opts.get("proxy_host"):
        proxy = get_proxy_dict(opts)

    # Create SimpleClient for a REST connection to the Resilient services
    url = "https://{0}:{1}".format(opts.get("host", ""), opts.get("port", 443))
    simple_client_args = {"org_name": opts.get("org"),
                          "proxies": proxy,
                          "base_url": url,
                          "verify": verify}
    if opts.get("log_http_responses"):
        LOG.warn("Logging all HTTP Responses from Resilient to %s", opts["log_http_responses"])
        simple_client = LoggingSimpleClient
        simple_client_args["logging_directory"] = opts["log_http_responses"]
    else:
        simple_client = SimpleClient

    resilient_client = simple_client(**simple_client_args)

    if opts.get("resilient_mock"):
        # Use a Mock for the Resilient Rest API
        LOG.warn("Using Mock '%s' for Resilient REST API", opts["resilient_mock"])
        module_path, class_name = opts["resilient_mock"].rsplit('.', 1)
        path, module_name = os.path.split(module_path)
        sys.path.insert(0, path)
        module = importlib.import_module(module_name)
        LOG.info("Looking for %s in %s", class_name, dir(module))
        mock_class = getattr(module, class_name)
        res_mock = mock_class(org_name=opts.get("org"), email=opts["email"])
        resilient_client.session.mount("https://", res_mock.adapter)

    userinfo = resilient_client.connect(opts["email"], opts["password"])

    # Validate the org, and store org_id in the opts dictionary
    LOG.debug(json.dumps(userinfo, indent=2))
    if(len(userinfo["orgs"])) > 1 and opts.get("org") is None:
        raise Exception("User is a member of multiple organizations; please specify one.")
    if(len(userinfo["orgs"])) > 1:
        for org in userinfo["orgs"]:
            if org["name"] == opts.get("org"):
                opts["org_id"] = org["id"]
    else:
        opts["org_id"] = userinfo["orgs"][0]["id"]

    # Check if action module is enabled and store to opts dictionary
    org_data = resilient_client.get('')
    resilient_client.actions_enabled = org_data["actions_framework_enabled"]

    return resilient_client


class TLSHttpAdapter(HTTPAdapter):
    """
    Adapter that ensures that we use the best available SSL/TLS version.
    Some environments default to SSLv3, so we need to specifically ask for
    the highest protocol version that both the client and server support.
    Despite the name, SSLv23 can select "TLS" protocols as well as "SSL".
    """
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=ssl.PROTOCOL_SSLv23)


class SimpleHTTPException(Exception):
    """Exception for HTTP errors."""
    def __init__(self, response):
        """
        Args:
          response - the Response object from the get/put/etc.
        """
        super(SimpleHTTPException, self).__init__(u"{0}:  {1}".format(response.reason, response.text))

        self.response = response

class PatchConflictException(SimpleHTTPException):
    """Exception for patch conflicts."""
    def __init__(self, response, patch_status):
        super(PatchConflictException, self).__init__(response)

        self.patch_status = patch_status

class NoChange(Exception):
    """Exception that can be raised within a get/put handler to indicate 'no change'
       (which then just bypasses the 'put')
    """
    pass


def _raise_if_error(response):
    """Helper to raise a SimpleHTTPException if the response.status_code is not 200.

    Args:
      response - the Response object from a get/put/etc.
    Raises:
      SimpleHTTPException - if response.status_code is not 200.
    """
    if response.status_code != 200:
        raise SimpleHTTPException(response)

def ensure_unicode(input_value):
    """ if input_value is type str, convert to unicode with utf-8 encoding """
    if sys.version_info.major >= 3:
        return input_value

    if not isinstance(input_value, basestring):
        return input_value
    elif isinstance(input_value, str):
        input_unicode = input_value.decode('utf-8')
    else:
        input_unicode = input_value

    input_unicode = unicodedata.normalize('NFKC', input_unicode)
    return input_unicode


def get_proxy_dict(opts):
    """ Creates a dictionary with proxy config to be sent to the SimpleClient """
    scheme = urlparse.urlparse(opts.proxy_host).scheme
    if not scheme:
        scheme = 'https'
        proxy_host = opts.proxy_host
    else:
        proxy_host = opts.proxy_host[len(scheme + "://"):]

    if opts.proxy_user and opts.proxy_password:
        proxy = {'https': '{0}://{1}:{2}@{3}:{4}/'.format(scheme, opts.proxy_user, opts.proxy_password,
                                                          proxy_host, opts.proxy_port)}
    else:
        proxy = {'https': '{0}://{1}:{2}'.format(scheme, proxy_host, opts.proxy_port)}

    return proxy


class SimpleClient(object):
    """Helper for using Resilient REST API."""

    def __init__(self, org_name=None, base_url=None, proxies=None, verify=None, cache_ttl=240):
        """
        Args:
          org_name - the name of the organization to use.
          base_url - the base URL to use.
          proxies - HTTP proxies to use, if any.
          verify - The name of a PEM file to use as the list of trusted CAs.
          cache_ttl - time to live for cached API responses
        """
        self.headers = {'content-type': 'application/json'}
        self.cookies = None
        self.org_id = None
        self.user_id = None
        self.base_url = u'https://app.resilientsystems.com/'
        self.org_name = ensure_unicode(org_name)
        if proxies:
            self.proxies = {ensure_unicode(key): ensure_unicode(proxies[key]) for key in proxies}
        else:
            self.proxies = None
        if base_url:
            self.base_url = ensure_unicode(base_url)
        self.verify = verify
        self.verify = ensure_unicode(verify)
        if verify is None:
            self.verify = True
        self.authdata = None
        self.session = requests.Session()
        self.session.mount(u'https://', TLSHttpAdapter())
        self.cache = TTLCache(maxsize=128, ttl=cache_ttl)

    def connect(self, email, password, timeout=None):
        """Performs connection, which includes authentication.

        Args:
          email - the email address to use for authentication.
          password - the password
          timeout - number of seconds to wait for response
        Returns:
          The Resilient session object (dict)
        Raises:
          SimpleHTTPException - if an HTTP exception occurs.
        """
        self.authdata = {
            u'email': ensure_unicode(email),
            u'password': ensure_unicode(password)
        }
        return self._connect(timeout=timeout)

    def _connect(self, timeout=None):
        """Establish a session"""
        response = self.session.post(u"{0}/rest/session".format(self.base_url),
                                     data=json.dumps(self.authdata),
                                     proxies=self.proxies,
                                     headers=self.__make_headers(),
                                     verify=self.verify,
                                     timeout=timeout)
        _raise_if_error(response)
        session = json.loads(response.text)
        orgs = session['orgs']
        selected_org = None
        if orgs is None or len(orgs) == 0:
            raise Exception("User is a member of no orgs")
        elif self.org_name:
            org_names = []
            for org in orgs:
                org_name = org['name']
                org_names.append(org_name)
                if ensure_unicode(org_name) == self.org_name:
                    selected_org = org
        else:
            org_names = [org['name'] for org in orgs]
            msg = u"Please specify the organization name to which you want to connect.  " + \
                  u"The user is a member of the following organizations: '{0}'"
            raise Exception(msg.format(u"', '".join(org_names)))

        if selected_org is None:
            msg = u"The user is not a member of the specified organization '{0}'."
            raise Exception(msg.format(self.org_name))

        if not selected_org.get("enabled", False):
            msg = "This organization is not accessible to you.\n\n" + \
                  "This can occur because of one of the following:\n\n" + \
                  "The organization does not allow access from your current IP address.\n" + \
                  "The organization requires authentication with a different provider than you are currently using.\n" + \
                  "Your IP address is {0}"
            raise Exception(msg.format(session["session_ip"]))

        self.all_orgs = [org for org in orgs if org.get("enabled")]
        self.org_id = selected_org['id']

        # set the X-sess-id token, which is used to prevent CSRF attacks.
        self.headers['X-sess-id'] = session['csrf_token']
        self.cookies = {
            'JSESSIONID': response.cookies['JSESSIONID']
        }
        self.user_id = session["user_id"]
        return session

    def __make_headers(self, co3_context_token=None, additional_headers=None):
        """Makes a headers dict, including the X-Co3ContextToken (if co3_context_token is specified)."""
        headers = self.headers.copy()
        if co3_context_token is not None:
            headers['X-Co3ContextToken'] = co3_context_token
        if isinstance(additional_headers, dict):
            headers.update(additional_headers)
        return headers

    def _execute_request(self, operation, url, **kwargs):
        """Execute a HTTP request.
           If unauthorized (likely due to a session timeout), retry.
        """
        result = operation(url, **kwargs)
        if result.status_code == 401:  # unauthorized, re-auth and try again
            self._connect()
            result = operation(url, **kwargs)
        return result

    def _keyfunc(self, uri, *args, **kwargs):
        """ function to generate cache key for cached_get """
        return uri

    def _get_cache(self):
        return self.cache

    def get(self, uri, co3_context_token=None, timeout=None):
        """Gets the specified URI.  Note that this URI is relative to <base_url>/rest/orgs/<org_id>.  So
        for example, if you specify a uri of /incidents, the actual URL would be something like this:

            https://app.resilientsystems.com/rest/orgs/201/incidents

        Args:
          uri
          co3_context_token
          timeout: number of seconds to wait for response
        Returns:
          A dictionary or array with the value returned by the server.
        Raises:
          SimpleHTTPException - if an HTTP exception occurs.
        """
        url = u"{0}/rest/orgs/{1}{2}".format(self.base_url, self.org_id, ensure_unicode(uri))
        response = self._execute_request(self.session.get,
                                         url,
                                         proxies=self.proxies,
                                         cookies=self.cookies,
                                         headers=self.__make_headers(co3_context_token),
                                         verify=self.verify,
                                         timeout=timeout)
        _raise_if_error(response)
        return json.loads(response.text)

    @cachedmethod(_get_cache, key=_keyfunc)
    def cached_get(self, uri, co3_context_token=None, timeout=None):
        """ Same as get, but checks cache first """
        return self.get(uri, co3_context_token, timeout)

    def get_const(self, co3_context_token=None, timeout=None):
        """
        Get the ConstREST endpoint.
        Endpoint for retrieving various constant information for this server.   This information is
        useful in translating names that the user sees to IDs that other REST API endpoints accept.
        For example, the incidentDTO has a field called "crimestatus_id". The valid values are stored
        in constDTO.crime_statuses.

        Args:
          co3_context_token
          timeout: number of seconds to wait for response
        Returns:
          ConstDTO as a dictionary
        Raises:
          SimpleHTTPException - if an HTTP exception occurs.
        """
        url = u"{0}/rest/const".format(self.base_url)
        response = self._execute_request(self.session.get,
                                         url,
                                         proxies=self.proxies,
                                         cookies=self.cookies,
                                         headers=self.__make_headers(co3_context_token),
                                         verify=self.verify,
                                         timeout=timeout)
        _raise_if_error(response)
        return json.loads(response.text)

    def get_content(self, uri, co3_context_token=None, timeout=None):
        """Gets the specified URI.  Note that this URI is relative to <base_url>/rest/orgs/<org_id>.  So
        for example, if you specify a uri of /incidents, the actual URL would be something like this:

            https://app.resilientsystems.com/rest/orgs/201/incidents

        Args:
          uri
          co3_context_token
          timeout: number of seconds to wait for response
        Returns:
          The raw value returned by the server for this resource.
        Raises:
          SimpleHTTPException - if an HTTP exception occurs.
        """
        url = u"{0}/rest/orgs/{1}{2}".format(self.base_url, self.org_id, ensure_unicode(uri))
        response = self._execute_request(self.session.get,
                                         url,
                                         proxies=self.proxies,
                                         cookies=self.cookies,
                                         headers=self.__make_headers(co3_context_token),
                                         verify=self.verify,
                                         timeout=timeout)
        _raise_if_error(response)
        return response.content

    def post(self, uri, payload, co3_context_token=None, timeout=None):
        """
        Posts to the specified URI.
        Note that this URI is relative to <base_url>/rest/orgs/<org_id>.  So for example, if you
        specify a uri of /incidents, the actual URL would be something like this:

            https://app.resilientsystems.com/rest/orgs/201/incidents
        Args:
           uri
           payload
           co3_context_token
          timeout: number of seconds to wait for response
        Returns:
          A dictionary or array with the value returned by the server.
        Raises:
          SimpleHTTPException - if an HTTP exception occurs.
        """
        url = u"{0}/rest/orgs/{1}{2}".format(self.base_url, self.org_id, ensure_unicode(uri))
        payload_json = json.dumps(payload)
        response = self._execute_request(self.session.post,
                                         url,
                                         data=payload_json,
                                         proxies=self.proxies,
                                         cookies=self.cookies,
                                         headers=self.__make_headers(co3_context_token),
                                         verify=self.verify,
                                         timeout=timeout)
        _raise_if_error(response)
        return json.loads(response.text)

    def _patch(self, uri, patch, co3_context_token=None, timeout=None):
        """Internal method used to call the underlying server patch endpoint"""
        url = u"{0}/rest/orgs/{1}{2}".format(self.base_url, self.org_id, ensure_unicode(uri))
        if isinstance(patch, dict):
            payload_json = json.dumps(patch)
        else:
            payload_json = json.dumps(patch.to_dict())

        hdrs = {"handle_format": "names"}
        response = self._execute_request(self.session.patch,
                                         url,
                                         data=payload_json,
                                         proxies=self.proxies,
                                         cookies=self.cookies,
                                         headers=self.__make_headers(co3_context_token,
                                                                     additional_headers=hdrs),
                                         verify=self.verify,
                                         timeout=timeout)

        return response

    def _handle_patch_response(self, response, patch, callback):
        """Helper to determine if a patch retry is needed.  Will only return True if the server responds with a
        409 or if the patch apply failed with field failures and the caller asked to overwrite conflicts."""
        if response.status_code == 409:
            # Just retry again, no adjustments.  The server can return 409 if there is a DB-level conflict.
            LOG.info("Retrying patch unchanged due to server CONFLICT")
            return True

        if response.status_code == 200:
            json = response.json()

            LOG.debug(json)

            patch_status = PatchStatus(json)

            if not patch_status.is_success() and patch_status.has_field_failures():
                LOG.info("Patch conflict detected - invoking callback")

                before = patch.get_old_values()

                try:
                    callback(response, patch_status, patch)
                except NoChange:
                    # Callback explicitly indicated that it didn't want to apply the change, so just
                    # return False here to stop processing.
                    #
                    LOG.debug("callback indicated no change after conflict - skipping")
                    return False

                if not patch.has_changes():
                    LOG.debug("callback removed all conflicts from patch - no need to re-issue")
                    return False

                # Make sure something in the patch has actually changed, otherwise we'd
                # just re-issue the same patch and get into a loop.
                after = patch.get_old_values()

                if before == after:
                    raise ValueError("invoked callback did not change the patch object, but returned True")

                return True

        # Raise an exception if there's some non-200 response.
        _raise_if_error(response)

        # Don't want to retry and got a 200 response.  There may or may not be field_failures.
        # Handling that is now up to the caller of the patch method.
        return False

    @staticmethod
    def _patch_overwrite_callback(response, patch_status, patch):
        """
        Callback to use when the caller specified overwrite_conflict=True in the patch call.
        """
        patch.update_for_overwrite(patch_status)

    @staticmethod
    def _patch_raise_callback(response, patch_status, patch):
        """
        Callback to use when the caller specified overwrite_conflict=False in the patch call.
        """

        # Got a conflict and no callback specified.  Just raise an exception.
        raise PatchConflictException(response, patch_status)

    def patch(self, uri, patch, co3_context_token=None, timeout=None, overwrite_conflict=False):
        """
        PATCH request to the specified URI.
        Note that this URI is relative to <base_url>/rest/orgs/<org_id>.  So for example, if you
        specify a uri of /incidents, the actual URL would be something like this:

            https://app.resilientsystems.com/rest/orgs/201/incidents

        :param uri: the URI on which patch is to be invoked
        :param patch: Patch object to apply
        :param co3_context_token: the Co3ContextToken from a CAF message (if the caller is
          a CAF message processor.
        :param timeout: Number of seconds to wait for response
        :param overwrite_conflict: always overwrite fields in conflict.  Note that if True, the passed-in patch
          object will be modified if necessary.
        :return: The response object.
        :raises SimpleHTTPException: if an HTTP exception or patch conflict occurs.
        :raises PatchStatusException: If the patch failed to apply (and overwrite_conflict is False).
        """
        if overwrite_conflict:
            # Re-issue patch with intent to overwrite conflicts.
            callback = SimpleClient._patch_overwrite_callback
        else:
            # Raise an exception on conflict.
            callback = SimpleClient._patch_raise_callback

        return self.patch_with_callback(uri, patch, callback, co3_context_token, timeout)

    def patch_with_callback(self, uri, patch, callback, co3_context_token=None, timeout=None):
        """
        PATCH request to the specified URI.  If the patch application fails because of field conflicts,
        the specified callback is invoked, allowing the caller to adjust the patch as necessary.
        :param uri: the URI on which patch is to be invoked
        :param patch: Patch object to apply
        :param callback: Function/lambda to invoke when a patch conflict is detected.  The function/lambda must be
          of the following form:
            def my_callback(response, patch_status, patch)
        :param co3_context_token: the Co3ContextToken from a CAF message (if the caller is
          a CAF message processor.
        :param timeout: Number of seconds to wait for response
        :return: The response object.
        """
        response = self._patch(uri, patch, co3_context_token, timeout)

        while self._handle_patch_response(response, patch, callback):
            response = self._patch(uri, patch, co3_context_token, timeout)

        return response

    def post_attachment(self, uri, filepath, filename=None, mimetype=None, data=None, co3_context_token=None, timeout=None):
        """
        Upload a file to the specified URI
        e.g. "/incidents/<id>/attachments" (for incident attachments)
        or,  "/tasks/<id>/attachments" (for task attachments)

        :param uri: The REST URI for posting
        :param filepath: the path of the file to post
        :param filename: optional name of the file when posted
        :param mimetype: optional override for the guessed MIME type
        :param data: optional dict with additional MIME parts (not required for file attachments, but used in artifacts)
        :param co3_context_token: Action Module context token, if responding to an Action Module event
        :param timeout: optional timeout (seconds)
        """
        filepath = ensure_unicode(filepath)
        if filename:
            filename = ensure_unicode(filename)
        url = u"{0}/rest/orgs/{1}{2}".format(self.base_url, self.org_id, ensure_unicode(uri))
        mime_type = mimetype or mimetypes.guess_type(filename or filepath)[0] or "application/octet-stream"
        with open(filepath, 'rb') as filehandle:
            attachment_name = filename or os.path.basename(filepath)
            multipart_data = {'file': (attachment_name, filehandle, mime_type)}
            multipart_data.update(data or {})
            encoder = MultipartEncoder(fields=multipart_data)
            headers = self.__make_headers(co3_context_token,
                                          additional_headers={'content-type': encoder.content_type})
            response = self._execute_request(self.session.post,
                                             url,
                                             data=encoder,
                                             proxies=self.proxies,
                                             cookies=self.cookies,
                                             headers=headers,
                                             verify=self.verify,
                                             timeout=timeout)
            _raise_if_error(response)
            return json.loads(response.text)

    def post_artifact_file(self, uri, artifact_type, artifact_filepath, description=None, value=None, mimetype=None, co3_context_token=None, timeout=None):
        """
        Post a file artifact to the specified URI
        e.g. "/incidents/<id>/artifacts/files"

        :param uri: The REST URI for posting
        :param artifact_type: the artifact type name ("IP Address", etc) or type ID
        :param artifact_filepath: the path of the file to post
        :param description: optional description for the artifact
        :param value: optional value for the artifact
        :param mimetype: optional override for the guessed MIME type
        :param co3_context_token: Action Module context token, if responding to an Action Module event
        :param timeout: optional timeout (seconds)

        """
        artifact = {
            "type": artifact_type,
            "value": value or "",
            "description": description or ""
        }
        mimedata = {
            "artifact": json.dumps(artifact)
        }
        return self.post_attachment(uri,
                                    artifact_filepath,
                                    mimetype=mimetype,
                                    data=mimedata,
                                    co3_context_token=co3_context_token,
                                    timeout=timeout)

    def search(self, payload, co3_context_token=None, timeout=None):
        """
        Posts to the SearchExREST endpoint.
        Endpoint for performing full text searches through incidents and incident child objects
        (tasks, incident comments, task comments, milestones, artifacts, incident attachments,
        task attachments, and data tables).

        Args:
          payload: the SearchExInputDTO parameters for performing a search, as a dictionary
          co3_context_token
          timeout: number of seconds to wait for response
        Returns:
          List of results, as an array of SearchExResultDTO
        Raises:
          SimpleHTTPException - if an HTTP exception occurs.
        """
        url = u"{0}/rest/search_ex".format(self.base_url)
        payload_json = json.dumps(payload)
        response = self._execute_request(self.session.post,
                                         url,
                                         data=payload_json,
                                         proxies=self.proxies,
                                         cookies=self.cookies,
                                         headers=self.__make_headers(co3_context_token),
                                         verify=self.verify,
                                         timeout=timeout)
        _raise_if_error(response)
        return json.loads(response.text)

    def _get_put(self, uri, apply_func, co3_context_token=None, timeout=None):
        """Internal helper to do a get/apply/put loop
        (for situations where the put might return a 409/conflict status code)
        """
        url = u"{0}/rest/orgs/{1}{2}".format(self.base_url, self.org_id, ensure_unicode(uri))
        response = self._execute_request(self.session.get,
                                         url,
                                         proxies=self.proxies,
                                         cookies=self.cookies,
                                         headers=self.__make_headers(co3_context_token),
                                         verify=self.verify,
                                         timeout=timeout)
        _raise_if_error(response)
        payload = json.loads(response.text)
        try:
            apply_func(payload)
        except NoChange:
            return payload
        payload_json = json.dumps(payload)
        response = self._execute_request(self.session.put,
                                         url,
                                         data=payload_json,
                                         proxies=self.proxies,
                                         cookies=self.cookies,
                                         headers=self.__make_headers(co3_context_token),
                                         verify=self.verify,
                                         timeout=timeout)
        if response.status_code == 200:
            return json.loads(response.text)
        elif response.status_code == 409:
            return None
        _raise_if_error(response)
        return None

    def get_put(self, uri, apply_func, co3_context_token=None, timeout=None):
        """Performs a get, calls apply_func on the returned value, then calls self.put.
        If the put call returns a 409 error, then retry.

        Args:
          uri - the URI to use.  Note that this is expected to be relative to the org.
          apply_func - a function to call on the object returned by get.  This is expected
          to alter the object with the desired changes.
          co3_context_token - the Co3ContextToken from a CAF message (if the caller is
          a CAF message processor.
          timeout - number of seconds to wait for response
        Returns;
          The object returned by the put operation (converted from JSON to a Python dict).
        Raises:
          Exception if the get or put returns an unexpected status code.
        """
        while True:
            obj = self._get_put(uri, apply_func, co3_context_token=co3_context_token, timeout=timeout)
            if obj:
                return obj
        return None

    def put(self, uri, payload, co3_context_token=None, timeout=None):
        """
        Puts to the specified URI.
        Note that this URI is relative to <base_url>/rest/orgs/<org_id>.  So for example, if you
        specify a uri of /incidents, the actual URL would be something like this:

            https://app.resilientsystems.com/rest/orgs/201/incidents
        Args:
           uri
           payload
           co3_context_token
          timeout: number of seconds to wait for response
        Returns:
          A dictionary or array with the value returned by the server.
        Raises:
          SimpleHTTPException - if an HTTP exception occurs.
        """
        url = u"{0}/rest/orgs/{1}{2}".format(self.base_url, self.org_id, ensure_unicode(uri))
        payload_json = json.dumps(payload)
        response = self._execute_request(self.session.put,
                                         url,
                                         data=payload_json,
                                         proxies=self.proxies,
                                         cookies=self.cookies,
                                         headers=self.__make_headers(co3_context_token),
                                         verify=self.verify,
                                         timeout=timeout)
        _raise_if_error(response)
        return json.loads(response.text)

    def delete(self, uri, co3_context_token=None, timeout=None):
        """Deletes the specified URI.

        Args:
          uri
          co3_context_token
          timeout: number of seconds to wait for response
        Returns:
          A dictionary or array with the value returned by the server.
        Raises:
          SimpleHTTPException - if an HTTP exception occurs.
        """
        url = u"{0}/rest/orgs/{1}{2}".format(self.base_url, self.org_id, ensure_unicode(uri))
        response = self._execute_request(self.session.delete,
                                         url,
                                         proxies=self.proxies,
                                         cookies=self.cookies,
                                         headers=self.__make_headers(co3_context_token),
                                         verify=self.verify,
                                         timeout=timeout)
        if response.status_code == 204:
            # 204 - No content is OK for a delete
            return None
        _raise_if_error(response)
        return json.loads(response.text)


class LoggingSimpleClient(SimpleClient):
    """ Simple Client version that logs all Resilient REST API responses to disk.  Useful when building a Mock."""
    def __init__(self, logging_directory="", *args, **kwargs):
        super(LoggingSimpleClient, self).__init__(*args, **kwargs)
        try:
            directory = os.path.expanduser(logging_directory)
            directory = os.path.expandvars(directory)
            assert(os.path.exists(directory))
            self.logging_directory = directory
        except Exception as e:
            raise Exception("Response Logging Directory %s does not exist!",
                            logging_directory)

    def _log_response(self, response, *args, **kwargs):
        """ Log Headers and JSON from a Requests Response object """
        url = urlparse.urlparse(response.url)
        filename = "_".join((str(response.status_code), "{0}",
                             response.request.method,
                             url.path, url.params,
                             datetime.datetime.now().isoformat())).replace('/', '_').replace(':', '-')
        with open(os.path.join(self.logging_directory,
                               filename.format("JSON")), "w+") as logfile:
            logfile.write(json.dumps(response.json(), indent=2))
        with open(os.path.join(self.logging_directory,
                               filename.format("HEADER")), "w+") as logfile:
            logfile.write(json.dumps(dict(response.headers), indent=2))

    def _connect(self, *args, **kwargs):
        """ Connect to Resilient and log response """
        normal_post = self.session.post
        self.session.post = lambda *args, **kwargs: normal_post(
            hooks=dict(response=self._log_response), *args, **kwargs)
        session = super(LoggingSimpleClient, self)._connect(*args, **kwargs)
        self.session.post = normal_post
        return session

    def _execute_request(self, operation, url, **kwargs):
        """Execute a HTTP request and log response.
           If unauthorized (likely due to a session timeout), retry.
        """
        def wrapped_operation(url, **kwargs):
            return operation(url, hooks=dict(response=self._log_response),
                             **kwargs)
        return super(LoggingSimpleClient, self)._execute_request(
            wrapped_operation, url, **kwargs)
