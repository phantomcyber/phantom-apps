# File: cloudflare_consts.py
#
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# API Endpoints
CLOUDFLARE_ZONES_ENDPOINT = 'zones'
CLOUDFLARE_FWRULE_ENDPOINT = 'zones/{zone_id}/firewall/rules'
CLOUDFLARE_FILTERS_ENDPOINT = 'zones/{zone_id}/filters'

# Other constants
CLOUDFLARE_FILTER_RULE_IP = '(ip.src eq {ip})'
CLOUDFLARE_FILTER_RULE_UA = '(http.user_agent eq "{ua}") or (http.user_agent contains "{ua}")'

CLOUDFLARE_DUPLICATES_ERRCODE = 10102
CLOUDFLARE_VALID_ACTIONS = {'allow': True, 'block': False}

# Error messages
CLOUDFLARE_INVALID_ACTION_ERR = 'Unknown action "{action}". Supported values are [' + ', '.join(
    CLOUDFLARE_VALID_ACTIONS) + ']'
CLOUDFLARE_ERR_CODE_MSG = "Error code unavailable"
CLOUDFLARE_ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
CLOUDFLARE_PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
CLOUDFLARE_PARSE_RESPONSE_ERR_MSG = "Cannot parse response from server"
