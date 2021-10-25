# File: ds_pagination_grouping_iterator.py
#
# Copyright (c) 2020-2021 Digital Shadows Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
from .ds_model import DSModel


class DSPaginationGroupingIterator(object):
    """
    Iterator that will Stream page groups of DSModel objects from the Provider.

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

    def current_page_offset(self):
        return int(self._page['current_page']['offset'])

    def current_page_size(self):
        return int(self._page['current_page']['size'])

    def __len__(self):
        return int(self._page['total'])

    def __iter__(self):
        return self

    def __next__(self):
        if self._page is None:
            self._page = next(self._provider)

        ds_model_group = []
        for ds_model_json in self._page['content']:
            ds_model_group.append(self._cls.from_json(ds_model_json))

        self._page = None
        return ds_model_group
