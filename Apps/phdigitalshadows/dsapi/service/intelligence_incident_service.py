#
# Copyright (c) 2017 Digital Shadows Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from datetime import date

from .ds_base_service import DSBaseService
from .ds_find_service import DSFindService
from ..model.intelligence_incident import IntelligenceIncident
from ..model.intelligence_incident_ioc import IntelligenceIncidentIoc

class IntelligenceIncidentService(DSFindService):

    def __init__(self, ds_api_key, ds_api_secret_key, proxy=None):
        super(IntelligenceIncidentService, self).__init__(ds_api_key, ds_api_secret_key, proxy=proxy)

    def find_all(self, view=None):
        """
        Streams all intelligenceIncident objects retrieved from the Digital Shadows API.

        :param view: IncidentsView
        :return: IntelligenceIncident generator
        """

        if view is None:
            view = IntelligenceIncidentService.intelligence_incidents_view()

        return self._find_all('/api/intel-incidents/find',
                              view,
                              IntelligenceIncident)

    def find_all_pages(self, view=None):
        """
        Streams all IntelligenceIncident objects retrieved from the Digital Shadows API in page groups.

        :param view: IncidentsView
        :return: IntelligenceIncident generator
        """

        if view is None:
            view = IntelligenceIncidentService.intelligence_incidents_view()

        return self._find_all_pages('/api/intel-incidents',
                                    view,
                                    IntelligenceIncident)

    def find_intel_incident_by_id(self, intel_incident_id=None):
        """
        Streams all Incident review objects retrieved from the Digital Shadows API.

        :param view: Intelligence Incident ID
        :return: Incident Reviews
        """
        return self._request('/api/intel-incidents/'+str(intel_incident_id))

    def find_intel_incident_ioc_by_id(self, intel_incident_id=None, view=None):
        """
        Streams all Incident review objects retrieved from the Digital Shadows API.

        :param view: Intelligence Incident ID
        :return: Incident Reviews
        """

        if view is None:
            view = IntelligenceIncidentService.intelligence_incident_ioc_view()

        return self._read_all_pages('/api/intel-incidents/' + str(intel_incident_id) + '/iocs', view, IntelligenceIncidentIoc)


    @staticmethod
    @DSBaseService.paginated()
    @DSBaseService.sorted('published')
    def intelligence_incidents_view(since='1970-01-01', until=date.today(), date_range_field='occurred', date_range='P30D',
                       severities=None, tag_operator='AND', tags=None, types=None,
                       with_feedback=True, without_feedback=True,
                       reverse=False, page_size=500, sort_property='occurred', identifier=None):
        return {
            "filter": {
                "identifier": "" if identifier is None else identifier,
                "dateRange": date_range,
                "dateRangeField": date_range_field,
                "severities": [] if severities is None else severities,
                "tagOperator": tag_operator,
                "tags": [] if tags is None else tags,
                "types": [] if types is None else types,
                "withFeedback": "true" if with_feedback else "false",
                "withoutFeedback": "true" if without_feedback else "false"
            },
            "pagination": {
                "offset": "0",
                "size": page_size,
            },
            "sort": {
                "direction": "ASCENDING" if reverse else "DESCENDING",
                "property": sort_property
            }
        }

    @staticmethod
    @DSBaseService.paginated()
    @DSBaseService.sorted('value')
    def intelligence_incident_ioc_view(types=None, value=None, reverse=False, page_size=500, sort_property='value'):
        return {
            "filter": {
                "types": [] if types is None else types,
                "value": "" if value is None else value
            },
            "pagination": {
                "offset": "0",
                "size": page_size,
            },
            "sort": {
                "direction": "ASCENDING" if reverse else "DESCENDING",
                "property": sort_property
            }
        }
