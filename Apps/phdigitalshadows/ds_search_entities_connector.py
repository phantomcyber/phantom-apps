#
# Copyright (c) 2020 Digital Shadows Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

import phantom.app as phantom
from phantom.action_result import ActionResult


from digital_shadows_consts import DS_API_KEY_CFG, DS_API_SECRET_KEY_CFG

from dsapi.service.search_entities_service import SearchEntitiesService
from bs4 import UnicodeDammit


class DSSearchEntitiesConnector(object):

    def __init__(self, connector):
        """
        :param connector: DigitalShadowsConnector
        """
        self._connector = connector

        config = connector.get_config()
        self._ds_api_key = UnicodeDammit(config[DS_API_KEY_CFG]).unicode_markup.encode('utf-8')
        self._ds_api_secret_key = config[DS_API_SECRET_KEY_CFG]

    def search_entities(self, param):
        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)

        self._connector.save_progress("process started...!!! ")

        # type = param.get('types').split(',')
        type = ["CLIENT_INCIDENT", "DATA_BREACH", "AGGREGATE_DATA_BREACH", "INTELLIGENCE", "TECHNICAL_SOURCE", "WEB_SOURCE"]
        date_range = param.get('date_range')
        query = param.get('query')
        """
        incident_types = param.get('incident_types')
        incident_subtypes = param.get('incident_subtypes')
        incident_severities = param.get('incident_severities')
        web_page_networks = param.get('web_page_networks')
        forum_post_networks = param.get('forum_post_networks')
        marketplace_listing_networks = param.get('marketplace_listing_networks')
        market_places = param.get('marketplaces')
        chat_protocols = param.get('chat_protocols')
        chat_servers = param.get('chat_servers')
        chat_channels = param.get('chat_channels')
        threat_level_types = param.get('threat_level_types')
        web_page_site_categories = param.get('web_page_site_categories')
        forum_post_site_categories = param.get('forum_post_site_categories')
        blog_names = param.get('blog_names')
        date_period = param.get('date_period')
        start_date = param.get('from')
        end_date = param.get('until')
        """

        search_service = SearchEntitiesService(self._ds_api_key, self._ds_api_secret_key)
        """
        search_view = search_service.search_entity_view(types=type, dateRange=date_range, incidentTypes=incident_types, incidentSubtypes=incident_subtypes,
                                                        incidentSeverities=incident_severities, webPageNetworks=web_page_networks,
                                                        forumPostNetworks=forum_post_networks, marketplaceListingNetworks=marketplace_listing_networks,
                                                        marketplaces=market_places, chatProtocols=chat_protocols, chatServers=chat_servers,
                                                        chatChannels=chat_channels, threatLevelTypes=threat_level_types,
                                                        webPageSiteCategories=web_page_site_categories, forumPostSiteCategories=forum_post_site_categories,
                                                        blogNames=blog_names, datePeriod=date_period, from_date=start_date,
                                                        until=end_date, query_string=query)
        """
        search_view = search_service.search_entity_view(dateRange=date_range, query_string=query, types=type)
        self._connector.save_progress("View: {}".format(search_view))
        try:
            search_entity_pages = search_service.find_all_pages(view=search_view)
            # self._connector.save_progress("entity: " + str(search_entity_pages))
            entity_total = len(search_entity_pages)
        except StopIteration:
            error_message = 'No Search Entity objects retrieved from the Digital Shadows API in page groups'
            return action_result.set_status(phantom.APP_ERROR, "Error Details: {0}".format(error_message))
        if entity_total > 0:
            summary = {
                'entity_count': entity_total,
                'entity_found': True
            }
            action_result.update_summary(summary)
            for entity_page in search_entity_pages:
                for entity in entity_page:
                    # self._connector.save_progress("entity payload: " + str(entity.payload))
                    action_result.add_data(entity.payload)
            action_result.set_status(phantom.APP_SUCCESS, 'String search entities are fetched')
        else:
            summary = {
                'entity_count': 0,
                'entity_found': False
            }
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS, 'Entities not found for search string')
        return action_result.get_status()
