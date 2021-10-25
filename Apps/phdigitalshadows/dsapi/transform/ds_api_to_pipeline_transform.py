# File: ds_api_to_pipeline_transform.py
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
class DSAPIToPipelineTransform(object):

    @staticmethod
    def apply(cls, json, pipeline_range):
        """
        Transform Digital Shadows pipeline api data to Pipeline object.
        
        :type pipeline_range: PipelineRange
        :param cls: Pipeline constructor 
        :param json: api data
        :param pipeline_range:
        :return: Pipeline
        """
        date_from = json['from']
        date_until = json['until']
        for stage in json['stages']:
            stage[str('date_range')] = str(pipeline_range)
            stage[str('from')] = str(date_from)
            stage[str('until')] = str(date_until)

            stage_type = stage['type']
            if stage_type == 'INCIDENTS':
                incidents = stage
            elif stage_type == 'ANALYST_ASSESSED':
                analyst_assessed = stage
            elif stage_type == 'ALL_MENTIONS':
                all_mentions = stage
        return cls(incidents, analyst_assessed, all_mentions)
