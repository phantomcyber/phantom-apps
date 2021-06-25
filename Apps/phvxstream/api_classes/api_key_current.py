from api_classes.api_caller import ApiCaller


class ApiKeyCurrent(ApiCaller):
    endpoint_url = '/key/current'
    endpoint_auth_level = ApiCaller.CONST_API_AUTH_LEVEL_RESTRICTED
    request_method_name = ApiCaller.CONST_REQUEST_METHOD_GET
