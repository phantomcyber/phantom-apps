# File: api_report_file.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from api_classes.api_caller import ApiCaller


class ApiReportFile(ApiCaller):
    endpoint_url = '/report/@id/file/@type'
    request_method_name = ApiCaller.CONST_REQUEST_METHOD_GET
    api_expected_data_type = ApiCaller.CONST_EXPECTED_DATA_TYPE_FILE
    endpoint_auth_level = ApiCaller.CONST_API_AUTH_LEVEL_DEFAULT


