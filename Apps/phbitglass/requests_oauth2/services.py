# File: services.py
#
# Copyright (c) 2021 Bitglass App Inc.
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
from requests_oauth2 import OAuth2


class GoogleClient(OAuth2):
    site = "https://accounts.google.com"
    authorization_url = "/o/oauth2/auth"
    token_url = "/o/oauth2/token"
    scope_sep = " "


class FacebookClient(OAuth2):
    site = "https://www.facebook.com/"
    authorization_url = "/dialog/oauth"
    token_url = "/oauth/access_token"
    scope_sep = " "


class InstagramClient(OAuth2):
    site = "https://api.instagram.com"
    authorization_url = "/oauth/authorize"
    token_url = "/oauth/access_token"
    scope_sep = " "
