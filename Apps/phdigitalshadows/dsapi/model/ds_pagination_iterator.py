#
# Copyright (c) 2017 Digital Shadows Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from .ds_model import DSModel


class DSPaginationIterator(object):
    """
    Iterator that will Stream all DSModel objects from the Provider.

    Provider *must* be a scrolling_request generator which yields a Digital Shadows page dictionary.
    Digital Shadows page dictionary:
    {
      'content': [],
      'currentPage: {
        'offset': int,
        'size': int
      },
      'total': int
    }
    """

    def __init__(self, provider, cls):
        """
        :type provider: generator
        :type cls: DSModel
        """
        self._provider = provider
        self._cls = cls

        self._page = next(self._provider)
        self._i = 0
        self._len = len(self._page['content'])

    def current_page_offset(self):
        return int(self._page['current_page']['offset'])

    def current_page_size(self):
        return int(self._page['current_page']['size'])

    def __len__(self):
        return int(self._page['total'])

    def __iter__(self):
        return self

    def next(self):
        if self._i >= self._len:
            self._page = next(self._provider)
            self._i = 0
            self._len = len(self._page['content'])

        ds_model_json = self._page['content'][self._i]
        self._i += 1
        return self._cls.from_json(ds_model_json)
