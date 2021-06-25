from api_classes.api_caller import ApiCaller


class ApiSearchHash(ApiCaller):
    endpoint_url = '/search/hash'
    endpoint_auth_level = ApiCaller.CONST_API_AUTH_LEVEL_RESTRICTED
    request_method_name = ApiCaller.CONST_REQUEST_METHOD_POST
