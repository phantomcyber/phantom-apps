# File: api_submit_online_file.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from api_classes.api_caller import ApiCaller


class ApiSubmitOnlineFile(ApiCaller):
    endpoint_url = '/submit/url-to-file'
    request_method_name = ApiCaller.CONST_REQUEST_METHOD_POST
    endpoint_auth_level = ApiCaller.CONST_API_AUTH_LEVEL_RESTRICTED
