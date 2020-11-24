#
# Copyright (c) 2017 Digital Shadows Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

import json
import time
import base64

from functools import wraps

from ..config import ds_api_host, ds_api_base

from .ds_abstract_service import DSAbstractService


class DSBaseService(DSAbstractService):
    """
    Base Service that implements common operations for all DS services.
    """

    def __init__(self, ds_api_key, ds_api_secret_key, proxy=None):
        super(DSBaseService, self).__init__(proxy=proxy)
        self._hash = base64.b64encode('{}:{}'.format(ds_api_key, ds_api_secret_key))
        self._url_base = '{}{}'.format(ds_api_host, ds_api_base)

    def _headers(self, with_content_type=True):
        headers = {
            'Authorization': 'Basic {}'.format(self._hash),
        }
        if with_content_type:
            headers['Content-Type'] = 'application/json'

        return headers

    def _request(self, path, method='GET', body=None, headers=None):
        """
        Send a request to the Digital Shadows API.

        :param path: API endpoint path, does not require host. eg. /api/session-user
        :param method:
        :param body:
        :param headers:
        :return: tuple(response, content)
        """
        url = '{}{}'.format(self._url_base, path)
        headers = self._headers() if headers is None else headers
        response, content = super(DSBaseService, self)._request(url,
                                                                method=method,
                                                                body=str(body).replace("'", '"'),
                                                                headers=headers)
        if int(response['status']) == 200:
            return json.loads(content)
        else:
            raise RuntimeError('{} responded with status code {}'.format(url, response['status']))

    def _request_post(self, path, method='POST', body=None, headers=None):
        """
        Send a request to the Digital Shadows API.

        :param path: API endpoint path, does not require host. eg. /api/session-user
        :param method:
        :param body:
        :param headers:
        :return: tuple(response, content)
        """
        url = '{}{}'.format(self._url_base, path)
        headers = self._headers() if headers is None else headers
        
        response, content = super(DSBaseService, self)._request(url,
                                                                method=method,
                                                                body=str(body).replace("'", '"'),
                                                                headers=headers)
        if int(response['status']) in (200, 204):
            if content != "":
                res_text = json.loads(content)
            else:
                res_text = ""
            post_response = {
              'status': response['status'],
              'message': 'SUCCESS',
              'content': []
            }
            post_response['content'].append(res_text)
            return post_response
        else:
            raise RuntimeError('{} responded with status code {}'.format(url, response['status']))

    def _scrolling_request(self, path, method='GET', body=None, headers=None):
        """
        Scrolls through a paginated response from the Digital Shadows API.

        :param path: API endpoint path, does not require host. eg. /api/session-user
        :param method:
        :param body: View object - requires pagination field, see DSBaseService.paginated decorator
        :return: tuple(response, content)
        """
        assert 'pagination' in body
        paginated_view = body
        url = '{}{}'.format(self._url_base, path)
        headers = self._headers() if headers is None else headers

        scrolling = True
        while scrolling:
            response, content = super(DSBaseService, self)._request(url,
                                                                    method,
                                                                    body=str(paginated_view).replace("'", '"'),
                                                                    headers=headers)

            if int(response['status']) == 200:
                data = json.loads(content)
                offset = data['currentPage']['offset']
                size = data['currentPage']['size']
                total = data['total']
                if offset + size < total:
                    paginated_view['pagination']['offset'] = offset + size
                else:
                    scrolling = False
                yield data
            elif int(response['status']) == 429:
                # rate limited, wait before resuming scroll requests
                time.sleep(1)
            else:
                scrolling = False

    def valid_credentials(self):
        """
        Checks if the provided Digital Shadows credentials are valid.

        :return: bool
        """
        path = '/api/session-user'
        url = '{}{}'.format(self._url_base, path)
        response, content = super(DSBaseService, self)._request(url,
                                                                headers=self._headers(with_content_type=False))
        return int(response['status']) == 200

    @staticmethod
    def paginated(offset=0, size=500):
        def paginated_decorator(view_function):
            @wraps(view_function)
            def view_wrapper(*args, **kwargs):
                pagination = {
                    'pagination': {
                        'offset': offset,
                        'size': size
                    }
                }
                view = view_function(*args, **kwargs)
                pagination.update(view)
                return pagination
            return view_wrapper
        return paginated_decorator

    @staticmethod
    def sorted(sort_property, reverse=False):
        def sorted_decorator(view_function):
            @wraps(view_function)
            def view_wrapper(*args, **kwargs):
                sort = {
                    'sort': {
                        'property': sort_property,
                        'direction': "ASCENDING" if reverse else "DESCENDING"
                    }
                }
                view = view_function(*args, **kwargs)
                sort.update(view)
                return sort
            return view_wrapper
        return sorted_decorator
