# File: api_report_state.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from api_classes.api_caller import ApiCaller


class ApiReportState(ApiCaller):
    endpoint_url = '/report/@id/state'
    endpoint_auth_level = ApiCaller.CONST_API_AUTH_LEVEL_RESTRICTED
    request_method_name = ApiCaller.CONST_REQUEST_METHOD_GET


