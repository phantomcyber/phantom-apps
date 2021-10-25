# File: api_report_summary.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from api_classes.api_caller import ApiCaller


class ApiReportSummary(ApiCaller):
    endpoint_url = '/report/@id/summary'
    endpoint_auth_level = ApiCaller.CONST_API_AUTH_LEVEL_RESTRICTED
    request_method_name = ApiCaller.CONST_REQUEST_METHOD_GET
