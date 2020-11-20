#
# Copyright (c) 2017 Digital Shadows Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from .ds_base_service import DSBaseService
from .ds_find_service import DSFindService

from ..model.data_breach import DataBreach


class DataBreachService(DSFindService):

    def __init__(self, ds_api_key, ds_api_secret_key, proxy=None):
        super(DataBreachService, self).__init__(ds_api_key, ds_api_secret_key, proxy=proxy)

    def find_all(self, view=None):
        """
        Streams all DataBreach objects retrieved from the Digital Shadows API.

        :param view: DataBreachView
        :return: DataBreach generator
        """

        if view is None:
            view = DataBreachService.data_breach_view()

        return self._find_all('/api/data-breach',
                              view,
                              DataBreach)

    def find_all_pages(self, view=None):
        """
        Streams all DataBreach objects retrieved from the Digital Shadows API in page groups.

        :param view: DataBreachView
        :return: DataBreach generator
        """

        if view is None:
            view = DataBreachService.data_breach_view()

        return self._find_all_pages('/api/data-breach',
                                    view,
                                    DataBreach)

    def find_data_breach_by_id(self, breach_id=None):
        """
        Streams all Incident review objects retrieved from the Digital Shadows API.

        :param view: Intelligence Incident ID
        :return: Incident Reviews
        """
        return self._request('/api/data-breach/'+str(breach_id))

    @staticmethod
    @DSBaseService.paginated(size=500)
    @DSBaseService.sorted('published')
    def data_breach_view(published='ALL', username=None, domain_names_on_records=None, reposted_credentials=None,
                         severities=None, statuses=None, alerted=False, minimum_total_records=None,
                         reverse=None):
        view = {
            'filter': {
                'published': published,
                'domainNamesOnRecords': [] if domain_names_on_records is None else domain_names_on_records,
                'repostedCredentials': [] if reposted_credentials is None else reposted_credentials,
                'severities': [] if severities is None else severities,
                'statuses': [] if statuses is None else statuses,
                'alerted': 'true' if alerted else 'false'
            }
        }
        if username is not None:
            view['filter']['username'] = username

        if minimum_total_records is not None:
            view['filter']['minimumTotalRecords'] = minimum_total_records

        if reverse is not None:
            view['sort'] = {
                'direction': 'ASCENDING' if reverse else 'DESCENDING',
                'property': 'published'
            }

        return view
