# File: pipeline_service.py
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
from ..model.pipeline import Pipeline


class PipelineRange(object):

    THIRTY_DAYS = 'THIRTY_DAYS'
    TWO_WEEKS = 'TWO_WEEKS'
    YEAR = 'YEAR'


class PipelineService(DSBaseService):

    def __init__(self, ds_api_key, ds_api_secret_key, proxy=None):
        self._api_base = '/api/incidents'
        super(PipelineService, self).__init__(ds_api_key, ds_api_secret_key, proxy=proxy)

    def get(self, pipeline_view):
        """
        Get Pipeline data from Digital Shadows API.
        
        :type pipeline_view: tuple
        :param pipeline_view: (PipelineView, view)
        :return: Pipeline 
        """
        pipeline_range, view = pipeline_view
        content = self._request('{}/pipeline'.format(self._api_base),
                                method='POST',
                                body=view)
        return Pipeline.from_json(content, pipeline_range)

    @staticmethod
    def pipeline_view(pipeline_range):
        """
        :type pipeline_range: PipelineRange
        :param pipeline_range: Pipeline range enum
        :return: tuple (PipelineView, view dict)
        """
        if pipeline_range == PipelineRange.THIRTY_DAYS:
            date_range = "P30D"
        elif pipeline_range == PipelineRange.TWO_WEEKS:
            date_range = "P2W"
        elif pipeline_range == PipelineRange.YEAR:
            date_range = "P1Y"
        else:
            raise ValueError('Invalid Pipeline Range')

        return (pipeline_range,
                {
                    "filter": {
                        "dateRange": "{}".format(date_range),
                    },
                })
