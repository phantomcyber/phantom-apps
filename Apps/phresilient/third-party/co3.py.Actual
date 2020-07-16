# -*- coding: utf-8 -*-

import requests
import json
import ssl
import mimetypes
import os
import unicodedata
import sys
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
from requests_toolbelt.multipart.encoder import MultipartEncoder


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
        input_unicode =  input_value.decode('utf-8')
    else:
        input_unicode = input_value
            
    input_unicode = unicodedata.normalize('NFKC', input_unicode)
    return input_unicode

class SimpleClient(object):
    """Helper for using Resilient REST API."""

    def __init__(self, org_name=None, base_url=None, proxies=None, verify=None):
        """
        Args:
          org_name - the name of the organization to use.
          base_url - the base URL to use.
          proxies - HTTP proxies to use, if any.
          verify - The name of a PEM file to use as the list of trusted CAs.
        """
        self.headers = {'content-type': 'application/json'}
        self.cookies = None
        self.org_id = None
        self.user_id = None
        self.base_url = u'https://app.resilientsystems.com/'
        self.org_name = ensure_unicode(org_name)
        if proxies:
            self.proxies = [ensure_unicode(proxy) for proxy in proxies]
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

    def connect(self, email, password, timeout=None):
        """Performs connection, which includes authentication.

        Args:
          email - the email address to use for authentication.
          password - the password
          timeout - number of seconds to wait for response
        Returns:
          The Resilient session object (dict)
        Raises:
          SimpleHTTPException - if an HTTP exception occurrs.
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

    def get(self, uri, co3_context_token=None, timeout=None):
        """Gets the specified URI.  Note that this URI is relative to <base_url>/rest/orgs/<org_id>.  So
        for example, if you specify a uri of /incidents, the actual URL would be something like this:

            https://app.resilientsystems.com/rest/orgs/201/incidents

        Args:
          uri
          co3_context_token
          timeout - number of seconds to wait for response
        Returns:
          A dictionary or array with the value returned by the server.
        Raises:
          SimpleHTTPException - if an HTTP exception occurrs.
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

    def get_content(self, uri, co3_context_token=None, timeout=None):
        """Gets the specified URI.  Note that this URI is relative to <base_url>/rest/orgs/<org_id>.  So
        for example, if you specify a uri of /incidents, the actual URL would be something like this:

            https://app.resilientsystems.com/rest/orgs/201/incidents

        Args:
          uri
          co3_context_token
          timeout - number of seconds to wait for response
        Returns:
          The raw value returned by the server for this resource.
        Raises:
          SimpleHTTPException - if an HTTP exception occurrs.
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
          timeout - number of seconds to wait for response
        Returns:
          A dictionary or array with the value returned by the server.
        Raises:
          SimpleHTTPException - if an HTTP exception occurrs.
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

    def post_attachment(self, uri, filepath, filename=None, mimetype=None, co3_context_token=None, timeout=None):
        """Upload a file to the specified URI"""
        filepath = ensure_unicode(filepath)
        if filename:
            filename = ensure_unicode(filename)
        url = u"{0}/rest/orgs/{1}{2}".format(self.base_url, self.org_id, ensure_unicode(uri))
        mime_type = mimetype or mimetypes.guess_type(filename or filepath)[0] or "application/octet-stream"
        with open(filepath, 'rb') as filehandle:
            attachment_name = filename or os.path.basename(filepath)
            multipart_data = {'file': (attachment_name, filehandle, mime_type)}
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
          timeout - number of seconds to wait for response
        Returns:
          A dictionary or array with the value returned by the server.
        Raises:
          SimpleHTTPException - if an HTTP exception occurrs.
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
          timeout - number of seconds to wait for response
        Returns:
          A dictionary or array with the value returned by the server.
        Raises:
          SimpleHTTPException - if an HTTP exception occurrs.
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

