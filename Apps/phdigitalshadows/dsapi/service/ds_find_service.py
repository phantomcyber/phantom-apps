# File: ds_find_service.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from .ds_base_service import DSBaseService
from ..model.ds_model import DSModel
from ..model.ds_pagination_iterator import DSPaginationIterator
from ..model.ds_pagination_grouping_iterator import DSPaginationGroupingIterator


class DSFindService(DSBaseService):
    """
    Generic Service that implements find_all and find_all_pages for Digital Shadows API objects.
    """

    def __init__(self, ds_api_key, ds_api_secret_key, proxy=None):
        super(DSFindService, self).__init__(ds_api_key, ds_api_secret_key, proxy=proxy)

    def _find_all(self, endpoint, view, cls):
        """
        Streams all DSModel objects retrieved from the Digital Shadows API.

        :type endpoint: str
        :type view: dict
        :type cls: DSModel
        :param endpoint: Digital Shadows API endpoint eg. /api/data-breach
        :param view: Digital Shadows endpoint View
        :param cls: DSModel class to be instantiated
        :return: DSModel
        """

        path = '{}/find'.format(endpoint)
        provider = self._scrolling_request(path,
                                           method='POST',
                                           body=view)
        return DSPaginationIterator(provider, cls)

    def _find_all_pages(self, endpoint, view, cls):
        """
        Streams all DSModel objects retrieved from the Digital Shadows API in page groups.

        :type endpoint: str
        :type view: dict
        :type cls: DSModel
        :param endpoint: Digital Shadows API endpoint eg. /api/data-breach
        :param view: Digital Shadows endpoint View
        :param cls: DSModel class to be instantiated
        :return: DSModel
        """

        path = '{}/find'.format(endpoint)
        provider = self._scrolling_request(path,
                                           method='POST',
                                           body=view)
        return DSPaginationGroupingIterator(provider, cls)

    def _read_all_pages(self, endpoint, view, cls):
        """
        Streams all DSModel objects retrieved from the Digital Shadows API in page groups.

        :type endpoint: str
        :type view: dict
        :type cls: DSModel
        :param endpoint: Digital Shadows API endpoint eg. /api/data-breach
        :param view: Digital Shadows endpoint View
        :param cls: DSModel class to be instantiated
        :return: DSModel
        """

        path = '{}'.format(endpoint)
        provider = self._scrolling_request(path,
                                           method='POST',
                                           body=view)
        return DSPaginationGroupingIterator(provider, cls)
