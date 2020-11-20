#
# Copyright (c) 2017 Digital Shadows Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from datetime import date

from .ds_base_service import DSBaseService
from .ds_find_service import DSFindService
from ..model.incident import Incident


class IncidentService(DSFindService):

    def __init__(self, ds_api_key, ds_api_secret_key, proxy=None):
        super(IncidentService, self).__init__(ds_api_key, ds_api_secret_key, proxy=proxy)

    def find_all(self, view=None):
        """
        Streams all Incident objects retrieved from the Digital Shadows API.

        :param view: IncidentsView
        :return: Incident generator
        """

        if view is None:
            view = IncidentService.incidents_view()

        return self._find_all('/api/incidents',
                              view,
                              Incident)

    def find_all_pages(self, view=None):
        """
        Streams all Incident objects retrieved from the Digital Shadows API in page groups.

        :param view: IncidentsView
        :return: Incident generator
        """

        if view is None:
            view = IncidentService.incidents_view()

        return self._find_all_pages('/api/incidents',
                                    view,
                                    Incident)

    def find_incident_by_id(self, incident_id=None):
        """
        Streams all Incident object retrieved from the Digital Shadows API.

        :param view: Incident ID
        :return: Incident data
        """
        return self._request('/api/incidents/'+str(incident_id))

    def find_all_reviews(self, incident_id=None):
        """
        Streams all Incident review objects retrieved from the Digital Shadows API.

        :param view: Incident ID
        :return: Incident Reviews
        """

        return self._request('/api/incidents/'+str(incident_id)+'/reviews')

    def post_incident_review(self, post_view=None, incident_id=None):
        """
        Streams all Incident review objects retrieved from the Digital Shadows API.

        :param view: Incident ID
        :return: Incident Reviews
        """
        return self._request_post('/api/incidents/'+str(incident_id)+'/reviews', body=post_view)

    @staticmethod
    @DSBaseService.paginated()
    @DSBaseService.sorted('published')
    def incidents_view(alerted=False, since='1970-01-01', until=date.today(), date_range_field='occurred', date_range='P30D',
                       severities=None, statuses=None, tag_operator='AND', tags=None, types=None,
                       with_content_removed=True, with_feedback=True, with_takedown=True,
                       without_content_removed=True, without_feedback=True, without_takedown=True,
                       reverse=False, page_size=500, sort_property='occurred', client_incidents_only=True, identifier=None):
        return {
            "filter": {
                "alerted": "true" if alerted else "false",
                "dateRange": date_range,
                "dateRangeField": date_range_field,
                "identifier": "" if identifier is None else identifier,
                "severities": [] if severities is None else severities,
                "statuses": ['READ', 'UNREAD', 'CLOSED'] if statuses is None else statuses,
                "tagOperator": tag_operator,
                "tags": [] if tags is None else tags,
                "types": [] if types is None else types,
                "withContentRemoved": "true" if with_content_removed else "false",
                "withFeedback": "true" if with_feedback else "false",
                "withTakedown": "true" if with_takedown else "false",
                "withoutContentRemoved": "true" if without_content_removed else "false",
                "withoutFeedback": "true" if without_feedback else "false",
                "withoutTakedown": "true" if without_takedown else "false",
            },
            "pagination": {
                "offset": "0",
                "size": page_size,
            },
            "sort": {
                "direction": "ASCENDING" if reverse else "DESCENDING",
                "property": sort_property
            },
            "subscribed": "false" if client_incidents_only else "true"
        }
