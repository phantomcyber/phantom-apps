# File: search_entities_service.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from datetime import date

from .ds_base_service import DSBaseService
from .ds_find_service import DSFindService
from ..model.search_entities import SearchEntities


class SearchEntitiesService(DSFindService):

    def __init__(self, ds_api_key, ds_api_secret_key, proxy=None):
        super(SearchEntitiesService, self).__init__(ds_api_key, ds_api_secret_key, proxy=proxy)

    def find_all(self, view=None):
        """
        Streams all Search Entity objects retrieved from the Digital Shadows API.

        :param view: SearchEntityView
        :return: Search Result generator
        """
        if view is None:
            view = SearchEntitiesService.search_entity_view()

        return self._find_all('/api/search',
                              view,
                              SearchEntities)

    def find_all_pages(self, view=None):
        """
        Streams all Search Entity objects retrieved from the Digital Shadows API in page groups.

        :param view: SearchEntityView
        :return: Search Result generator
        """

        if view is None:
            view = SearchEntitiesService.search_entity_view()

        return self._find_all_pages('/api/search',
                                    view,
                                    SearchEntities)

    @staticmethod
    @DSBaseService.paginated()
    def search_entity_view(tags=None, types=None, dateRange='P30D', incidentTypes=None, incidentSubtypes=None, incidentSeverities=None,
                           webPageNetworks=None, forumPostNetworks=None, marketplaceListingNetworks=None, marketplaces=None, chatProtocols=None,
                           chatServers=None, chatChannels=None, threatLevelTypes=None, webPageSiteCategories=None, forumPostSiteCategories=None,
                           blogNames=None, reverse=False, page_size=500, sort_property='relevance', query_string=''):
        return {
            "filter": {
                "tags": [] if tags is None else tags,
                "types": [] if types is None else types,
                "dateRange": dateRange,
                "incidentTypes": [] if incidentTypes is None else incidentTypes,
                "incidentSubtypes": [] if incidentSubtypes is None else incidentSubtypes,
                "incidentSeverities": [] if incidentSeverities is None else incidentSeverities,
                "webPageNetworks": [] if webPageNetworks is None else webPageNetworks,
                "forumPostNetworks": [] if forumPostNetworks is None else forumPostNetworks,
                "marketplaceListingNetworks": [] if marketplaceListingNetworks is None else marketplaceListingNetworks,
                "marketplaces": [] if marketplaces is None else marketplaces,
                "chatProtocols": [] if chatProtocols is None else chatProtocols,
                "chatServers": [] if chatServers is None else chatServers,
                "chatChannels": [] if chatChannels is None else chatChannels,
                "threatLevelTypes": [] if threatLevelTypes is None else threatLevelTypes,
                "webPageSiteCategories": [] if webPageSiteCategories is None else webPageSiteCategories,
                "forumPostSiteCategories": [] if forumPostSiteCategories is None else forumPostSiteCategories,
                "blogNames": [] if blogNames is None else blogNames
            },
            "pagination": {
                "offset": "0",
                "size": page_size,
            },
            "sort": {
                "direction": "ASCENDING" if reverse else "DESCENDING",
                "property": sort_property
            },
            "query": query_string
        }

