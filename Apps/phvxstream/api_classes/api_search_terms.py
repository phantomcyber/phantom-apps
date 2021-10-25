# File: api_search_terms.py
#
# Copyright (C) 2018 Hybrid Analysis GmbH
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
from api_classes.api_caller import ApiCaller


class ApiSearchTerms(ApiCaller):
    endpoint_url = '/search/terms'
    endpoint_auth_level = ApiCaller.CONST_API_AUTH_LEVEL_RESTRICTED
    request_method_name = ApiCaller.CONST_REQUEST_METHOD_POST
    params_map = {
        'file_type_substring': 'filetype_desc',
        'environment_id': 'env_id',
        'av_detection': 'av_detect',
        'av_family_substring': 'vx_family',
        'hashtag': 'tag',
        'similar_samples': 'similar_to',
        'imphash': 'imp_hash',
        'file_type': 'filetype',
        'file_name': 'filename',
    }

    verdict_map = {
        'whitelisted': 1,
        'no verdict': 2,
        'no specific threat': 3,
        'suspicious': 4,
        'malicious': 5
    }

    def map_params(self, params):
        for old, new in self.params_map.iteritems():
            if old in params:
                params[new] = params[old]
                del params[old]

        if 'verdict' in params:
            params['verdict'] = self.verdict_map[params['verdict']]

        return params
