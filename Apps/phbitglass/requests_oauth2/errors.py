# File: requests_oauth2/errors.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

class OAuth2Error(Exception):
    pass


class ConfigurationError(OAuth2Error):
    pass
