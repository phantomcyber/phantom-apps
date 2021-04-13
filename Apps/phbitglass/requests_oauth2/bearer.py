# File: requests_oauth2/bearer.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

from requests.auth import AuthBase


class OAuth2BearerToken(AuthBase):
    """Implements OAuth2 Bearer access token authentication.

    Pass this object via the `auth` parameter to a request or a
    session object in order to authenticate your requests.

    Example usage, once you have the `access_token`:

    >>> auth = OAuth2BearerToken(access_token)
    >>> requests.get("https://api.example.com/hello", auth=auth)
    <Response [200]>

    With a session:

    >>> with requests.Session() as s:
    ...     s.auth = auth
    ...     print(s.get("https://api.example.com/hello"))
    ...
    <Response [200]>

    """

    def __init__(self, access_token):
        self.access_token = access_token

    def __call__(self, request):
        request.headers['Authorization'] = 'Bearer {0}'.format(
            self.access_token
        )
        return request
