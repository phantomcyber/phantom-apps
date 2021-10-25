# File: pipeline.py
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
from ..transform.ds_api_to_pipeline_transform import DSAPIToPipelineTransform


class Pipeline(object):

    def __init__(self, incidents, analyst_assessed, all_mentions):
        self._incidents = incidents
        self._analyst_assessed = analyst_assessed
        self._all_mentions = all_mentions

    @property
    def incidents(self):
        return self._incidents

    @property
    def analyst_assessed(self):
        return self._analyst_assessed

    @property
    def all_mentions(self):
        return self._all_mentions

    def __str__(self):
        return 'Pipeline[incidents={}, analyst_assessed={}, all_mentions={}]'\
            .format(self._incidents, self.analyst_assessed, self._all_mentions)

    @classmethod
    def from_json(cls, json, pipeline_range):
        return DSAPIToPipelineTransform.apply(cls, json, pipeline_range)
