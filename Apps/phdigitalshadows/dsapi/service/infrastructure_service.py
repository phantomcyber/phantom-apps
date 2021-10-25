# File: infrastructure_service.py
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
from .ds_base_service import DSBaseService
from .ds_find_service import DSFindService

from ..model.infrastructure import Infrastructure


class InfrastructureService(DSFindService):

    def __init__(self, ds_api_key, ds_api_secret_key, proxy=None):
        super(InfrastructureService, self).__init__(ds_api_key, ds_api_secret_key, proxy=proxy)

    def find_all(self, view=None):
        """
        Streams all infrastructure objects retrieved from the Digital Shadows API.

        :param view: InfrastructureView
        :return: Infrastructure generator
        """

        if view is None:
            view = InfrastructureService.infrastructure_view()

        return self._find_all('/api/ip-ports',
                              view,
                              Infrastructure)

    def find_all_pages(self, view=None):
        """
        Streams all infrastructure objects retrieved from the Digital Shadows API in page groups.

        :param view: InfrastructureView
        :return: Infrastructure generator
        """

        if view is None:
            view = Infrastructure.infrastructure_view()

        return self._find_all_pages('/api/ip-ports',
                                    view,
                                    Infrastructure)

    @staticmethod
    @DSBaseService.paginated(size=500)
    @DSBaseService.sorted('published')
    def infrastructure_view(detectedopen='ALL', domainname=None, detectedclosed=False, markedclosed=False,
                         severities=None, alerted=False, reverse=None):
        view = {
            'filter': {
                'detectedOpen': detectedopen,
                'severities': [] if severities is None else severities,
                'alerted': 'true' if alerted else 'false',
                'markedClosed': 'true' if markedclosed else 'false',
                'detectedClosed': 'true' if detectedclosed else 'false'
            }
        }
        if domainname is not None:
            view['filter']['domainName'] = domainname

        if reverse is not None:
            view['sort'] = {
                'direction': 'ASCENDING' if reverse else 'DESCENDING',
                'property': 'published'
            }

        return view
