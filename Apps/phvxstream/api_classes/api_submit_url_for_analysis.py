from api_classes.api_caller import ApiCaller


class ApiSubmitUrlForAnalysis(ApiCaller):
    endpoint_url = '/submit/url-for-analysis'
    request_method_name = ApiCaller.CONST_REQUEST_METHOD_POST
    endpoint_auth_level = ApiCaller.CONST_API_AUTH_LEVEL_RESTRICTED

