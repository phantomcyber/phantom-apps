# File: data_breach_record_service.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from .ds_base_service import DSBaseService

from ..model.data_breach_record import DataBreachRecord
from ..model.ds_pagination_iterator import DSPaginationIterator
from ..model.ds_pagination_grouping_iterator import DSPaginationGroupingIterator


class DataBreachRecordService(DSBaseService):

    def __init__(self, ds_api_key, ds_api_secret_key, proxy=None):
        super(DataBreachRecordService, self).__init__(ds_api_key, ds_api_secret_key, proxy=proxy)

    def find_all(self, data_breach_id, view=None):

        if view is None:
            view = DataBreachRecordService.data_breach_records_view()

        path = '/api/data-breach/{}/records'.format(data_breach_id)
        provider = self._scrolling_request(path,
                                           method='POST',
                                           body=view)
        return DSPaginationIterator(provider, DataBreachRecord)

    def find_all_pages(self, data_breach_id, view=None):

        if view is None:
            view = DataBreachRecordService.data_breach_records_view()

        path = '/api/data-breach/{}/records'.format(data_breach_id)
        provider = self._scrolling_request(path,
                                           method='POST',
                                           body=view)
        return DSPaginationGroupingIterator(provider, DataBreachRecord)


    def read_all_records(self, view=None):
        """
        Streams all DataBreach objects retrieved from the Digital Shadows API in page groups.

        :param view: DataBreachRecordService
        :return: DataBreachRecord generator
        """

        if view is None:
            view = DataBreachRecordService.data_breach_records_view()
        path = '/api/data-breach-record/find'
        provider = self._scrolling_request(path,
                                           method='POST',
                                           body=view)
        return DSPaginationGroupingIterator(provider, DataBreachRecord)

    def find_data_breach_record_reviews(self, breach_id=None):
        """
        Streams all Incident review objects retrieved from the Digital Shadows API.

        :param view: Breach record ID
        :return: Incident Reviews
        """
        return self._request('/api/data-breach-record/'+str(breach_id)+'/reviews')

    def post_data_breach_record_review(self, post_view=None, breach_record_id=None):
        """
        Streams all Incident review objects retrieved from the Digital Shadows API.

        :param view: Breach record ID
        :return: Incident Reviews
        """
        return self._request_post('/api/data-breach-record/'+str(breach_record_id)+'/reviews', body=post_view)

    @staticmethod
    @DSBaseService.paginated(size=500)
    @DSBaseService.sorted('username')
    def data_breach_records_view(published="ALL", distinction=None, username=None, password=None,
                                 domain_names=None, review_statuses=None):
        view = {
            'filter': {
                'published': published,
                'domainNames': [] if domain_names is None else domain_names,
                'reviewStatuses': [] if review_statuses is None else review_statuses
            }
        }

        if distinction is not None:
            view['filter']['distinction'] = distinction

        if username is not None:
            view['filter']['username'] = username

        if password is not None:
            view['filter']['password'] = password

        return view
